"""
Adds/Removes Stations from Access Points.
"""

from pox.core import core
from pox.messenger import *

log = core.getLogger()

G_RATES = [1,2,6,11,12,18,24,36,48,54]
G_RATES_LEN = len(G_RATES)

GET_DPID = {"method":"transact", "params":["Open_vSwitch", {"op":"select","table":"Bridge","where":[],"columns":["datapath_id"]}], "id":1}

ADD_STATION = {"method":"transact","params":["Open_vSwitch",{"op":"insert","table":"WifiSta","row":{"addr":None,"vbssid":None}}],"id":1}

DEL_STATION = {"method":"transact","params":["Open_vSwitch",{"op":"delete","table":"WifiSta","where":[]}],"id":2}

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
        log.debug(msg)
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
                event.con.send(DEL_STATION)
            except (KeyError, TypeError) as e:
                pass

    def send_echo_reply(self, con, msg):
        con.send({"result":msg['params'],"error":None, 'id':msg['id']})

    def send_dpid_request(self, con):
        con.send(GET_DPID)

    def _handle_AddStation(self, event):
        log.debug("Received add station event")
        log.debug(event)
        add_json = ADD_STATION.copy()
        add_json["params"][1]["row"] = {"addr":event.src_addr, "vbssid": event.vbssid}
        log.debug("Adding Station %s to %d" % (event.src_addr, event.dpid))
        if self.connections.has_key(event.dpid):
            con = self.connections[event.dpid]
            con.send(add_json)
            log.debug(add_json)
        else:
            log.debug("key not found...")
            for key in self.connections.keys():
                log.debug("DPID : %x" % key)
        
class OvsDBManager(object):
    def __init__(self):
        core.listen_to_dependencies(self)
        log.debug("OvsDBManager Started")

    def _all_dependencies_met(self):
        log.debug("Dependencies Met!!")
        core.MessengerNexus.default_bot.add_bot(OvsDBBot)
        OvsDBBot(core.MessengerNexus.get_channel(""))

def launch():
    OvsDBManager()
