"""
A WiFi Authenticator.
"""
from wifi_base import *

import hashlib
from util import *

log = core.getLogger("WifiMessenger")
log_fsm = core.getLogger("WifiFSM")
log_mob = core.getLogger("WifiMobility")

all_stations = {}
all_aps = {}
all_vaps = {}
personal_aps = {}
phase_out = [True]

class Station(object):
    def __init__(self, addr):
        self.addr = addr # mac address of station
        self.dpid = None
        self.last_seen = time.time() # last heard from the AP.
        self.last_snr = 0 # SNR of last packet as reported form the dpid.
        self.state = 'SNIFF'
        log_fsm.debug("%012x : NONE -> %s" % (self.addr, self.state))

    def __str__(self):
        return "%x|%s|%x|%x\n" % (self.addr,self.state,self.dpid,self.vbssid)

class BackhaulSwitch(EventMixin):
    '''
    This should be a learning switch. NEC throws an error, 
    so hardcode stuff for now.
    '''
    _eventMixin_events = set([HostTimeout])

    def __init__(self, connection, transparent):
        #LearningSwitch.__init__(self, connection, transparent, parent=None)
        self.connection = connection
        self.transparent = transparent
        self.connection.addListeners(self)
        self.topo = BEHOP_TOPO
        if IS_GATES_NETWORK == True:
            self._setup_gates_switch()
        else:
            self._setup_studio5_switch()

    def _handle_FlowRemoved(self, event):
        '''
        Flow has expired at the switch - forward event to the main brain
        to see if the station is gone for good.
        The only entries that can timeout are the downlink flows from the backhaul switch to the hosts.
        All other flows are set with no timeout.
        '''        
        if event.timeout:
            addr = event.ofp.match.dl_dst
            packets = event.ofp.packet_count
            bytes = event.ofp.byte_count
            dur = event.ofp.duration_sec
            self.raiseEvent(HostTimeout(event.dpid, addr, packets, bytes, dur))

    def _setup_studio5_switch(self):
        # all ports should go to the uplinks to start with (split mgmt and data traffic).
        for ap, ap_port in self.topo.items():            
            self._set_simple_flow(ap_port, [BACKHAUL_DATA_UPLINK])
            self._set_simple_flow(ap_port, [BACKHAUL_MGMT_UPLINK], mac_src=EthAddr("%012x" % ap), priority=2)
            self._set_simple_flow(BACKHAUL_MGMT_UPLINK, [ap_port], mac_dst=EthAddr("%012x" % ap), priority=2)
            # drop packets destined to the AP coming from the data port...
            # workaround buggy dhcp leases from rescomp's DHCP.
            self._set_simple_flow(BACKHAUL_DATA_UPLINK, [], mac_dst=EthAddr("%012x" % ap), priority=2)
            # do not allow anything coming from the LAN port.
            lan_addr = get_lan_from_wan_1(ap)
            self._set_simple_flow(ap_port, [], mac_src=EthAddr("%012x" % lan_addr), priority=2)
            self._set_simple_flow(BACKHAUL_DATA_UPLINK, [], mac_dst=EthAddr("%012x" % lan_addr), priority=2)
            lan_addr = get_lan_from_wan_2(ap)
            self._set_simple_flow(ap_port, [], mac_src=EthAddr("%012x" % lan_addr), priority=2)
            self._set_simple_flow(BACKHAUL_DATA_UPLINK, [], mac_dst=EthAddr("%012x" % lan_addr), priority=2)
            
                
        # add flow for broadcast
        self._set_simple_flow(BACKHAUL_MGMT_UPLINK, self.topo.values(), mac_dst=EthAddr("ffffffffffff"), priority=2)
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, self.topo.values(), mac_dst=EthAddr("ffffffffffff"), priority=2)
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, self.topo.values(), mac_dst=EthAddr("01005E0000FB"), priority=2)
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, self.topo.values(), mac_dst=EthAddr("3333000000FB"), priority=2)
        self._set_simple_flow(BACKHAUL_MGMT_UPLINK, [], priority=1)
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, [], priority=1)

    def _setup_gates_switch(self):
        # all ports should go to the uplink to start with
        for ap, ap_port in self.topo.items():            
            self._set_simple_flow(ap_port, [BACKHAUL_DATA_UPLINK])
            self._set_simple_flow(BACKHAUL_DATA_UPLINK, [ap_port], mac_dst=EthAddr("%012x" % ap), priority=2)
            # do not allow anything coming from the LAN port.
            lan_addr = get_lan_from_wan_1(ap)
            self._set_simple_flow(ap_port, [], mac_src=EthAddr("%012x" % lan_addr), priority=2)
            self._set_simple_flow(BACKHAUL_DATA_UPLINK, [], mac_dst=EthAddr("%012x" % lan_addr), priority=2)
            lan_addr = get_lan_from_wan_2(ap)
            self._set_simple_flow(ap_port, [], mac_src=EthAddr("%012x" % lan_addr), priority=2)
            self._set_simple_flow(BACKHAUL_DATA_UPLINK, [], mac_dst=EthAddr("%012x" % lan_addr), priority=2)
            
                
        # add flow for broadcast
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, self.topo.values(), mac_dst=EthAddr("ffffffffffff"), priority=2)
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, self.topo.values(), mac_dst=EthAddr("01005E0000FB"), priority=2)
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, self.topo.values(), mac_dst=EthAddr("3333000000FB"), priority=2)
        self._set_simple_flow(BACKHAUL_DATA_UPLINK, [], priority=1)

    def _set_simple_flow(self,port_in, ports_out, priority=1,mac_src=None,mac_dst=None, ip_src=None, ip_dst=None,queue_id=None, dl_type=0x0800,idle_timeout=0):
        msg = of.ofp_flow_mod()
        msg.idle_timeout=idle_timeout
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.priority = priority
        msg.match.in_port = port_in
        if (mac_dst):
            msg.match.dl_dst = mac_dst
        if (mac_src):
            msg.match.dl_src = mac_src
        if (ip_dst or ip_src):
            msg.match.dl_type = dl_type
            if (ip_dst):
                msg.match.nw_dst = ip_dst
            if (ip_src):
                msg.match_nw_src = ip_src
        for port_out in ports_out:
            msg.actions.append(of.ofp_action_output(port = port_out))
        self.connection.send(msg)

    def _del_simple_flow(self, port_in, priority=1,mac_dst=None):
        msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        msg.match.in_port = port_in
        if (mac_dst):
            msg.match.dl_dst = mac_dst
        if priority:
            msg.match.priority = priority
        self.connection.send(msg)

class WifiAuthenticator(EventMixin):
    '''
    This is the main class for WifiAuthentication. It keeps track of all APs
    on a AP-map and spawns a WifiAuthenticateSwitch for each AP.
    * Monitors raw 80211 management events and generates Probe/Auth/Assoc Responses
    * Manages virtual-BSSID (vbssid)
    * Decides where to place a station and sets appropriate state to the related AP.
    * Talks to the Information Base (IB) and decides whether to move a station and where.
    * Monitors stations, checks for timeouts, etc.
    '''
    _eventMixin_events = set([AddStation, RemoveStation, MoveStation, UpdateBssidmask, SnrSummary,AddVBeacon,DelVBeacon])

    def __init__(self, transparent, wifimode):
        '''
        Setup vbssid map and placeholders for APs and stations.
        '''
        EventMixin.__init__(self)
        self.agg_msnger = AggBot(core.MessengerNexus.get_channel("MON_IB"), extra={'parent':self})
        core.openflow.addListeners(self)
        #core.openflow_discovery.addListenerByName("LinkEvent", self._handle_LinkEvent)
        self.all_aps = all_aps
        self.all_stations = all_stations
        self.transparent = transparent
        self.wifimode = wifimode
        self.bh_switch = None
        self.timer = None
        self.bw_timer = None
        self.set_timer()
        self.next_aid = 0x0001
        self.blacklisted_aps = []
        self.whitelisted_stas = []
        self.node_to_dpid = {}
        if USE_BLACKLIST == 1:
            self.blacklisted_aps = self.load_blacklisted_aps()
        if USE_WHITELIST == 1:
            self.whitelisted_stas = self.load_whitelisted_stas()
        self.load_phy_aps()
        self.load_static_vaps()
        
    def load_phy_aps(self):
        '''Statically create a placeholder object for all known Access Points.
        '''
        for ap_dpid in BEHOP_TOPO.keys():
            all_aps[ap_dpid] = PhyAP(None, self.transparent, ap_dpid, self.is_blacklisted(ap_dpid), 
                           self.whitelisted_stas, authenticator=self, phase_out = phase_out)
            all_aps[ap_dpid].addListeners(self)

    def load_static_vaps(self):
        '''
        Static VAP allocation---one per RadioAP.
        We don't care about bssidmask bitmap collission when 
        we have a one-to-one VAP allocation, so don't bother to
        do channel reuse.
        '''
        band_prefix_2GHz = 0x020000000000
        band_prefix_5GHz = 0x060000000000
        ap_prefix = 0x1
        for dpid in sorted(all_aps.keys()):
            phy_ap = all_aps[dpid]
            vbssid_2GHz = band_prefix_2GHz | ap_prefix
            vbssid_5GHz = band_prefix_5GHz | ap_prefix
            all_vaps[vbssid_2GHz] = VirtualAP(vbssid = vbssid_2GHz, parent_radioap = phy_ap.radioap_2GHz)
            all_vaps[vbssid_5GHz] = VirtualAP(vbssid = vbssid_5GHz, parent_radioap = phy_ap.radioap_5GHz)
            phy_ap.radioap_2GHz.virtual_aps[vbssid_2GHz] = all_vaps[vbssid_2GHz]
            phy_ap.radioap_5GHz.virtual_aps[vbssid_5GHz] = all_vaps[vbssid_5GHz]
            ap_prefix = ap_prefix << 1

    def load_broadcast_stas(self, num = 1):
        '''
        Add VAPs and stations to stress-test the broadcast scenario.
        '''
        vbssid_2GHz = 0x020000000001
        vbssid_5GHz = 0x060000000001
        aid = 1
        addr_2GHz = 0x020000000001
        for dpid in sorted(all_aps.keys()):
            for i in range(0,num):
                phy_ap = all_aps[dpid]
                phy_ap.radioap_2GHz.add_station(addr_2GHz,vbssid_2GHz,
                                                WifiStaParamsSample(addr = addr_2GHz,
                                                                    supp_rates = WLAN_2_GHZ_SUPP_RATES,
                                                                    listen_interval=100,
                                                                    capabilities=0x401,
                                                                    ht_capabilities = None),
                                                aid)
                aid += 1
                addr_2GHz += 1


    def load_topology(self):
        f = open(TOPOLOGY_FNAME,'r')

    def load_blacklisted_aps(self):
        b_aps = []
        f = open(BLACKLIST_FNAME,'r')
        for line in f.readlines():
            if line.startswith('#'):
                continue
            b_aps.append(int(line.rstrip(),16))
        f.close()
        log.info("Loading List of Blacklisted APs:")
        for ap in b_aps:
            log.info("Blacklisted AP : %012x" % ap)
        return b_aps

    def load_whitelisted_stas(self):
        log.debug("Loading List of Whitelisted Stas:")
        if (LOAD_WHITELIST_FROM_DB):
            w_stas =  load_sta_whitelist_from_db()
            self.node_to_dpid = w_stas
        else:
            w_stas =  load_sta_whitelist_from_file()
            self.node_to_dpid = w_stas
        for sta in w_stas:
            log.info("Whitelisted STA : %012x" % sta)
        return w_stas.keys()
    
    def is_blacklisted(self, dpid):
        if dpid in self.blacklisted_aps:
            return True
        return False

    def bw_update(self):
        self.whitelisted_stas = self.load_whitelisted_stas()
        self.blacklisted_aps = self.load_blacklisted_aps()
        # apply the new black/white-list to the Wifi APs.
        for dpid,ap in all_aps.items():
            ap.whitelisted_stas = self.whitelisted_stas 
            ap.is_blacklisted = self.is_blacklisted(dpid)                    

    def set_timer(self):
        '''
        Setup timer for stations timeout.
        '''
        if self.timer : self.timer.cancel()
        #self.timer = Timer(5, self.check_timeout_events, recurring=True)
        if self.bw_timer : self.bw_timer.cancel()
        self.bw_timer = Timer(BW_LIST_UPDATE_INTERVAL, self.bw_update, recurring=True)

    def delete_station(self, sta, update_bssidmask=True):
        '''
        Deletes a station from the AP-map, removes state from the AP itself, 
        and frees reserved vbssid.
        @sta the station to delete
        @update_bssidmask : flag for whether to update the bssidmask of the AP
        the station belongs to. In case there are multiple station-deletes (e.g. 
        periodic timeout events, it make sense to apply changes for all nodese once).
        '''
        if self.vbssid_map.has_key(sta.addr):
            # this might not work...
            self.removeStation(sta.dpid, sta.addr)
            #self.delVBeacon(sta.dpid,sta.vbssid)
            #del self.vbssid_map[sta.addr]
            #self.vbssid_pool.append(sta.vbssid)
        dpid = sta.dpid
        del all_stations[sta.addr]
        if update_bssidmask:
            self.update_bssidmask(dpid)

    def get_next_aid(self):
        '''
        Gives the next association-id (aid). Rotate among available aids.
        @TODO : ensure that there are no duplicate AIDs at the same AP.
        (probably need to maintain unique AID for each station...)
        '''
        cur_id = self.next_aid
        if self.next_aid == 0x7d7:
            self.next_aid = 0x0001
        else:
            self.next_aid += 1
        return cur_id
                        
    def _handle_ConnectionUp(self, event):
        '''
        Setup a Wifi AP for each new connection.
        '''
        log.debug("Connection %s" % (event.connection))
        if (event.dpid == BACKHAUL_SWITCH):
            log.debug("Adding Backhaul Switch as learning switch")
            self.bh_switch = BackhaulSwitch(event.connection, self.transparent)
            self.bh_switch.addListeners(self)
        else:
            # if we already know this DPID, just update the connection.
            if all_aps.has_key(event.dpid):
                log.warn("Updating connection for AP %x" % event.dpid)
                all_aps[event.dpid].update_connection(event.connection)
                return

    def _handle_ConnectionDown(self, event):
        '''
        Remove stations associated with this switch.
        '''
        log.debug("Connection terminated : %s (%012x" % (event.connection, event.dpid))
        if (event.dpid == BACKHAUL_SWITCH):
            log.debug("Removing Backhaul Switch...")
        else:
            if not all_aps.has_key(event.dpid) or event.connection != all_aps[event.dpid].connection:
                log.debug("Will not remove AP state---AP unkown or connection already updated...")
                return
        
    def get_or_create_personal_ap(self, event):
        '''Return the personal AP for this station. If one doesn't exist create it.'''
        if event.src_addr not in all_stations.keys():
            log.debug("Creating Personal AP for station %012x" % event.src_addr)
            sta = Station(event.src_addr)
            sta.aid = self.get_next_aid()
            log.debug("came here")
            all_stations[event.src_addr] = sta
            if self.wifimode == "defaultap":
                personal_ap = PersonalDefaultWiFiAP(sta)
            elif self.wifimode == "5g":
                personal_ap = PersonalDefaultWiFi5GHz(sta)
            elif self.wifimode == "2g":
                personal_ap = PersonalDefaultWiFi2GHz(sta)
            else:
                log.error("Unknown WiFi Mode for AP : %s" % self.wifimode)
                return

            log.debug("and came here")
            personal_aps[event.src_addr] = personal_ap
            log.debug("Here are the personal AP keys : %s" % personal_aps.keys())
        
        return personal_aps[event.src_addr]

    def _handle_ProbeRequest(self, event):
        # We haven't heard of this guy before, let's create a Personal AP as a placeholder.
        # it's the job of the personal-AP to decide what to do.
        personal_ap = self.get_or_create_personal_ap(event)
        personal_ap.handle_probe_request(event)

    def _handle_AuthRequest(self, event):
        personal_ap = self.get_or_create_personal_ap(event)
        personal_ap.handle_auth_request(event)

    def _handle_AssocRequest(self, event):
        personal_ap = self.get_or_create_personal_ap(event)
        personal_ap.handle_assoc_request(event)

    def _handle_ReassocRequest(self, event):
        personal_ap = self.get_or_create_personal_ap(event)
        personal_ap.handle_reassoc_request(event)

    def _handle_DisassocRequest(self, event):
        personal_ap = self.get_or_create_personal_ap(event)
        personal_ap.handle_disassoc_request(event)

    def _handle_DeauthRequest(self, event):
        personal_ap = self.get_or_create_personal_ap(event)
        personal_ap.handle_deauth_request(event)

    def set_station_flow(self,addr,dpid):
        if self.bh_switch:
            self.bh_switch._set_simple_flow(BACKHAUL_DATA_UPLINK, [self.bh_switch.topo[dpid]], priority=2,
                                            mac_dst=EthAddr(mac_to_str(addr)), idle_timeout = DEFAULT_HOST_TIMEOUT)

    def del_station_flow(self, addr, dpid):
        self.bh_switch._del_simple_flow(BACKHAUL_DATA_UPLINK,mac_dst=EthAddr(mac_to_str(addr)))
        
    def _handle_HostTimeout(self, event):
        '''
        Remove the state for this host.
        '''
        if event.dst_addr in personal_aps.keys():
            personal_ap = personal_aps[event.dst_addr]
        else:
            #nothing to do..
            return
        personal_ap.handle_host_timeout(event)

                        
def list_stations(state=None):
    if state == None:
        stas = [sta for sta in all_stations.values()]
    else:
        stas = [sta for sta in all_stations.values() if sta.state == state]
    idx = 1
    for sta in stas:
        print "%d. %012x:%s" % (idx, sta.addr,sta.state)
        idx += 1

def list_personal_aps():
    idx = 1
    for ap in personal_aps.values():
        print "%d %012x" % (idx, ap.sta.addr)
        idx += 1

def load_broadcast_stas(num=1):
    core.WifiAuthenticator.load_broadcast_stas(num)

def launch(transparent=False, wifimode="defaultap"):
    core.Interactive.variables['behop_stations'] = all_stations
    core.Interactive.variables['behop_aps'] = all_aps
    core.Interactive.variables['behop_phase_out'] = phase_out
    core.Interactive.variables['list_stations'] = list_stations
    core.Interactive.variables['list_personal_aps'] = list_personal_aps
    core.Interactive.variables['load_broadcast_stas'] = load_broadcast_stas
    core.registerNew(WifiAuthenticator, str_to_bool(transparent), wifimode)
