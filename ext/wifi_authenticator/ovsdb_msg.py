"""
Adds/Removes Stations from Access Points.
"""

from pox.core import core
from pox.messenger import *
from pox.lib.recoco import Timer

log = core.getLogger("WifiOvsDB")

G_RATES = [1,2,6,11,12,18,24,36,48,54]
G_RATES_LEN = len(G_RATES)

GET_DPID = {"method":"transact", "params":["Open_vSwitch", {"op":"select","table":"Bridge","where":[],"columns":["datapath_id"]}], "id":1}

ADD_STATION = {"method":"transact","params":["Open_vSwitch",{"op":"insert","table":"WifiSta","row":{"addr":None,"vbssid":None}}],"id":1}

DEL_STATION = {"method":"transact","params":["Open_vSwitch",{"op":"delete","table":"WifiSta","where":[]}],"id":2}

class SnrSummary(Event):
    def __init__(self, summary):
        Event.__init__(self)
        self.summary = summary
        
class AggService(EventMixin):
    _eventMixin_events = set([SnrSummary])

    def __init__(self, parent, con, event):
        EventMixin.__init__(self)
        self.addListeners(parent.parent)
        self.con = con
        self.parent = parent
        self.listeners = con.addListeners(self)
        self.count = 0
        self.timer = Timer(1, self.poll_snr, recurring=True)

        self._handle_MessageReceived(event, event.msg)

    def poll_snr(self):
        self.con.send({'CHANNEL':'MON_IB','query':'snr_summary'})

    def _handle_MessageReceived(self, event, msg):
        #log.info("Agg Received message : %s" % msg);
        if msg['query'] == 'snr_summary':
            self.raiseEvent(SnrSummary(msg['res']))
            #log.info("Overheard Stations")
            #log.info(["%s" % key for key in msg['res'].keys()])

    def _handle_ConnectionClosed(self, event):
        self.con.removeListeners(self.listeners)
        self.parent.clients.pop(self.con, None)
    

class AggBot(ChannelBot):
    def _init(self, extra):
        self.clients = {}
        self.parent = extra['parent']
    def _unhandled(self, event):
        connection = event.con
        if connection not in self.clients:
            self.clients[connection] = AggService(self, connection, event)

class OvsDBBot(ChannelBot, EventMixin):
    def __init__(self, channel, nexus = None, weak = False, extra = {}):
        ChannelBot.__init__(self, channel, nexus, weak, extra)
        self.connections = {}
        self.listenTo(core.WifiAuthenticator)
        log.debug("initialized OVSDBBot")

    def _handle_ChannelCreate(self, event):
        log.debug("Channel Created!")

    def _handle_ChannelJoin(self, event):
        log.debug("connection joined")

    def _handle_MessageReceived(self, event, msg):
        #log.debug(msg)
        if msg.has_key("method") and msg['method'] == 'echo':
            self.send_echo_reply(event.con, msg)
            if event.con not in self.connections.values():
                # ask the DPID from ovsdb - this should happen on connection...
                self.send_dpid_request(event.con)
        # hacky way to get the DPID
        elif msg.has_key("result"):
            try:
                dpid = int(msg["result"][0]["rows"][0]["datapath_id"],16)
                self.connections[dpid] = event.con
                log.debug("Appending OVSDB connection for %x" % dpid)
                log.debug("Removing existing stations")
                log.debug(DEL_STATION)
                event.con.send(DEL_STATION)
            except (KeyError, TypeError) as e:
                pass

    def send_echo_reply(self, con, msg):
        con.send({"result":msg['params'],"error":None, 'id':msg['id']})

    def send_dpid_request(self, con):
        con.send(GET_DPID)

    def _handle_AddStation(self, event):
        add_json = ADD_STATION.copy()
        _addr = "%012x" % event.src_addr
        _vbssid = "%012x" % event.vbssid
        add_json["params"][1]["row"] = {"addr":_addr, "vbssid": _vbssid}
        log.debug("Adding Station %s to %d" % (_addr, event.dpid))
        if self.connections.has_key(event.dpid):
            con = self.connections[event.dpid]
            con.send(add_json)
        else:
            log.debug("key not found...")
            for key in self.connections.keys():
                log.debug("DPID : %x" % key)

    def _handle_RemoveStation(self, event):
        rem_json = DEL_STATION.copy()
        _addr = "%012x" % event.src_addr
        rem_json["params"][1]["where"] = [["addr","==",_addr]]
        log.debug("Removing Station %x from AP %x" % (event.src_addr, event.dpid))
        if self.connections.has_key(event.dpid):
            con = self.connections[event.dpid]
            con.send(rem_json)
        else:
            log.debug("key not found...")
            for key in self.connections.keys():
                log.debug("DPID : %x" % key)
        
class MessengerManager(object):
    def __init__(self):
        core.listen_to_dependencies(self)
        log.debug("Messenger Service Started")

    def _all_dependencies_met(self):
        log.debug("Dependencies Met!!")
        core.MessengerNexus.default_bot.add_bot(OvsDBBot)
        OvsDBBot(core.MessengerNexus.get_channel(""))
        #AggBot(core.MessengerNexus.get_channel("MON_IB"))
        
def launch():
    MessengerManager()
