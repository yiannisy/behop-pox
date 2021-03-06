"""
Adds/Removes Stations from Access Points.
"""

from pox.core import core
from pox.messenger import *
from pox.lib.recoco import Timer
from wifi_helper import *

log = core.getLogger("WifiOvsDB")

G_RATES = [1,2,6,11,12,18,24,36,48,54]
G_RATES_LEN = len(G_RATES)

GET_DPID = {"method":"transact", "params":["Open_vSwitch", {"op":"select","table":"Bridge",
                                                            "where":[],"columns":["datapath_id"]}], "id":1}
ADD_STATION = {"method":"transact","params":["Wifi_vSwitch",{"op":"insert","table":"WifiSta","row":{"addr":None,"vbssid":None,"intf":None,"ht_capa":None,"sup_rates":["set",[]]}}],"id":1}
DEL_STATION = {"method":"transact","params":["Wifi_vSwitch",{"op":"delete","table":"WifiSta","where":[]}],"id":2}
DEL_STATION_2GHZ = {"method":"transact","params":["Wifi_vSwitch",{"op":"delete","table":"WifiSta","where":[["intf","==","wlan0"]]}],"id":2}
DEL_STATION_5GHZ = {"method":"transact","params":["Wifi_vSwitch",{"op":"delete","table":"WifiSta","where":[["intf","==","wlan1"]]}],"id":2}
UPDATE_BSSIDMASK = {"method":"transact", "params":["Wifi_vSwitch",{"op":"update","table":"WifiConfig","where":[],"row":{"bssidmask":None}}],"id":3}
ADD_VBEACON = {"method":"transact","params":["Wifi_vSwitch",{"op":"insert","table":"WifiBeacon","row":{"vbssid":None,"intf":None,}}],"id":4}
DEL_VBEACON = {"method":"transact","params":["Wifi_vSwitch",{"op":"delete","table":"WifiBeacon","where":[]}],"id":5}



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
        self.ovsdb_ids = {}
        self.listenTo(core.WifiAuthenticator)
        log.debug("initialized OVSDBBot")

    def send_ovsdb_msg(self, dpid, msg):
        con = self.connections[dpid]
        ovs_id = self.ovsdb_ids[dpid]
        if self.ovsdb_ids[dpid] == 1024:
            self.ovsdb_ids[dpid] = 2
        else:
            self.ovsdb_ids[dpid] +=1 
        msg['id'] = ovs_id
        con.send(msg)

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
                self.ovsdb_ids[dpid] = 1
                log.debug("Appending OVSDB connection for %012x" % dpid)
                log.debug("Clients for dpid %012x" % dpid)
                log.debug(core.WifiAuthenticator.node_to_dpid)
                nodes = [node for node in core.WifiAuthenticator.node_to_dpid.keys() if core.WifiAuthenticator.node_to_dpid[node] == dpid]
                bssidmask = 0xffffffffffff
                phyap = core.WifiAuthenticator.all_aps[dpid]
                log.debug("Deleting all existing beacons")
                self.send_ovsdb_msg(dpid,DEL_VBEACON)
                log.debug("Removing existing stations")
                self.send_ovsdb_msg(dpid, DEL_STATION_2GHZ)
                self.send_ovsdb_msg(dpid, DEL_STATION_5GHZ)
                log.debug("Resetting bssidmask")
                self._handle_UpdateBssidmask(UpdateBssidmask(dpid, "wlan0",0xffffffffffff))
                self._handle_UpdateBssidmask(UpdateBssidmask(dpid, "wlan1",0xffffffffffff))                
                for radioap in [phyap.radioap_2GHz, phyap.radioap_5GHz]:                    
                    log.debug("VAPs for %s (%012x) : %s" % (radioap.intf,phyap.dpid,radioap.virtual_aps.keys()))
                    for vbssid in radioap.virtual_aps.keys():
                        bssidmask &= ~(vbssid)
                        log.debug("Adding VBeacon for VirtualAP %012x (DPID:%012x)" % (vbssid,dpid))
                        self._handle_AddVBeacon(AddVBeacon(dpid,radioap.intf,vbssid))
                    log.debug("BSSIDMASK for %012x (%s) : %08x" % (dpid,radioap.intf,bssidmask))
                    self._handle_UpdateBssidmask(UpdateBssidmask(dpid,radioap.intf,bssidmask))
                    # Go through the nodes and reinstall state if this node is associated.
                    # (used to cover the case where ovs in the AP restarts and state gets desynced.
                    # for node in nodes:
                    #    if core.WifiAuthenticator.all_stations.has_key(node) and core.WifiAuthenticator.all_stations[node].state == 'ASSOC':
                    #        log.debug("Reinstalling state for associated station %012x" % (node))
                    #        station = core.WifiAuthenticator.all_stations[node]
                    #        ap = core.WifiAuthenticator.all_aps[dpid]
                    #        self._handle_AddStation(AddStation(dpid,intf,node,station.vbssid,station.aid,
                    #                                           station.params,ap.ht_capabilities_info))
            except (KeyError, TypeError) as e:
                pass

    def send_echo_reply(self, con, msg):
        con.send({"result":msg['params'],"error":None, 'id':msg['id']})

    def send_dpid_request(self, con):
        con.send(GET_DPID)

    def _handle_AddStation(self, event):
        params = event.params
        sta_flags = 0
        _addr = "%012x" % event.src_addr
        _vbssid = "%012x" % event.vbssid
        _sup_rates = byte_array_to_hex_str(params.supp_rates)
        if params.ext_rates:
            _ext_rates = byte_array_to_hex_str(params.ext_rates)
        else:
            _ext_rates = "0000"
        if params.ht_capabilities:
            _ht_capa_info = get_ht_capa_info(params.ht_capabilities['ht_capab_info'], event.ht_capabilities_info)
            _ht_capa_ampdu = params.ht_capabilities['a_mpdu']
            _ht_capa_mcs = byte_array_to_hex_str(params.ht_capabilities['mcs'])
            _ht_capa_ext = params.ht_capabilities['ext_capa']
            _ht_capa_txbf = params.ht_capabilities['txbf']
            _ht_capa_asel = params.ht_capabilities['asel']
        else:
            _ht_capa_info = 0
            _ht_capa_ampdu = 0
            _ht_capa_mcs = ""
            _ht_capa_ext = 0
            _ht_capa_txbf = 0
            _ht_capa_asel = 0
        add_json = ADD_STATION.copy()
        add_json["params"][1]["row"] = {"addr":_addr,"vbssid":_vbssid,
                                        "intf":event.intf,
                                        "sup_rates":_sup_rates,
                                        "ext_rates":_ext_rates,
                                        "sta_aid":event.aid,
                                        "sta_interval":params.listen_interval,
                                        "sta_capabilities":params.capabilities,
                                        "sta_flags":sta_flags,
                                        "ht_capa_info":_ht_capa_info,
                                        "ht_capa_ampdu":_ht_capa_ampdu,
                                        "ht_capa_mcs":_ht_capa_mcs,
                                        "ht_capa_ext":_ht_capa_ext,
                                        "ht_capa_txbf":_ht_capa_txbf,
                                        "ht_capa_asel":_ht_capa_asel}
        #"capabilities":event.params.capabilities,
        #                                "listen_interval":event.params.listen_interval,
        #                                "rates":event.params.supp_rates,"ext_rates":event.params.ext_rates}
        log.debug("ADD-STATION : %s" % add_json)
        log.debug("Adding Station %s to %x" % (_addr, event.dpid))
        if self.connections.has_key(event.dpid):
            self.send_ovsdb_msg(event.dpid,add_json)
        else:
            log.debug("key not found...")
            for key in self.connections.keys():
                log.debug("DPID : %x" % key)

    def _handle_RemoveStation(self, event):
        rem_json = DEL_STATION.copy()
        _addr = "%012x" % event.src_addr
        rem_json["params"][1]["where"] = [["addr","==",_addr],["intf","==",event.intf]]
        log.debug("Removing Station %x from AP %x" % (event.src_addr, event.dpid))
        if self.connections.has_key(event.dpid):
            self.send_ovsdb_msg(event.dpid,rem_json)
        else:
            log.debug("key not found...")
            for key in self.connections.keys():
                log.debug("DPID : %x" % key)

    def _handle_AddVBeacon(self, event):
        add_json = ADD_VBEACON.copy()
        _vbssid = "%012x" % event.vbssid
        add_json["params"][1]["row"]["vbssid"] = _vbssid
        add_json["params"][1]["row"]["intf"] = event.intf
        if self.connections.has_key(event.dpid):
            self.send_ovsdb_msg(event.dpid,add_json)                  
            
    def _handle_DelVBeacon(self, event):
        del_json = DEL_VBEACON.copy()
        _vbssid = "%012x" % event.vbssid
        del_json["params"][1]["where"] == [["vbssid","==",_vbssid],["intf","==",event.intf]]
        log.debug("Removing beacon for VBSSID %x (%x)" % (event.vbssid,event.dpid))
        if self.connections.has_key(event.dpid):
            self.send_ovsdb_msg(event.dpid,del_json)
        else:
            log.debug("key not found...")
            for key in self.connections.keys():
                log.debug("DPID : %x" % key)

    def _handle_UpdateBssidmask(self, event):
        upd_json = UPDATE_BSSIDMASK.copy()
        _bssidmask = "%012x" % event.bssidmask
        upd_json["params"][1]["row"]["bssidmask"] = _bssidmask
        #upd_json["params"][1]["row"]["intf"] = event.intf
        upd_json["params"][1]["where"] = [["intf","==",event.intf]]
        log.debug("Updating BSSIDMASK for AP %x : %x" % (event.dpid, event.bssidmask))
        if self.connections.has_key(event.dpid):
            self.send_ovsdb_msg(event.dpid,upd_json)
        else:
            log.debug("Cannot find connection handler for %012x" % dpid)
                          
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
