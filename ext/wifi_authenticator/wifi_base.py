from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str as mac_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.recoco import Timer
from ovsdb_msg import SnrSummary,AggService, AggBot, OvsDBBot
from pox.forwarding.l2_learning import LearningSwitch

import dpkt, binascii
from pox.lib.revent import *
from wifi_helper import *

from dpkt import NeedData
from pox.lib.addresses import EthAddr
from behop_config import *
from wifi_params import *
from behop_config import *



class RadioAP():
    '''This is an AP instance running on a physical interface.
    '''
    def __init__(self, channel = None, intf = None, parent_phyap = None):
        self.current_channel = channel
        self.intf = intf
        self.parent_phyap = parent_phyap
        self.virtual_aps = {}

        self.set_capabilities()

    def is_band_2GHZ(self):
        if self.current_channel <= WLAN_2_GHZ_CHANNEL_MAX:
            return True
        return False

    def get_virtual_ap(self, vbssid):
        if vbssid in self.virtual_aps.keys():
            return self.virtual_aps[vbssid]
        else:
            return None

    def set_capabilities(self):
        '''
        Set the capabilities advertised by this RadioAP according to the channel.
        '''
        if self.is_band_2GHZ():
            self.capabilities = WLAN_2_GHZ_CAPA
            self.ht_capabilities_info = WLAN_2_GHZ_HT_CAPA
            self.capa_exp = WLAN_2_GHZ_CAPA_EXP
            self.capa_mask = WLAN_2_GHZ_CAPA_MASK
            self.ht_capa_exp = WLAN_2_GHZ_HT_CAPA_EXP
            self.ht_capa_mask = WLAN_2_GHZ_HT_CAPA_MASK
            self.intf = WLAN_2_GHZ_INTF
            self.mon_port = WLAN_2_GHZ_MON_PORT
            self.wlan_port = WLAN_2_GHZ_WLAN_PORT
        else:
            self.capabilities = WLAN_5_GHZ_CAPA
            self.ht_capabilities_info = WLAN_5_GHZ_HT_CAPA
            self.capa_exp = WLAN_5_GHZ_CAPA_EXP
            self.capa_mask = WLAN_5_GHZ_CAPA_MASK
            self.ht_capa_exp = WLAN_5_GHZ_HT_CAPA_EXP
            self.ht_capa_mask = WLAN_5_GHZ_HT_CAPA_MASK
            self.intf = WLAN_5_GHZ_INTF
            self.mon_port = WLAN_5_GHZ_MON_PORT
            self.wlan_port = WLAN_5_GHZ_WLAN_PORT

    def send_packet_out(self, msg_raw):
        self.parent_phyap.send_packet_out(msg_raw, self.mon_port)

    def add_station(self, addr, vbssid, params, aid):
        '''
        Adds station state to the RadioAP (raise through WifiAuthenticator).
        '''
        phyap = self.parent_phyap
        phyap.authenticator.raiseEvent(AddStation(phyap.dpid, self.intf, 
                                   addr, vbssid, aid, params, 
                                   self.ht_capabilities_info))

    def del_station(self, addr):
        '''
        Remove the station state from the RadioAP.
        '''
        self.raiseEvent(RemoveStation(self.parent_phyap.dpid, self.intf, addr))

class DefaultWiFiFSM(FSM):
    def __init__(self):
        self.states = ['SNIFF','AUTH','ASSOC']
        self.inputs = ['ProbeReq','AuthReq','AssocReq','Timeout','DeauthReq','DisassocReq']
        FSM.__init__(self, 'SNIFF')
        self.add_transition('SNIFF','ProbeReq',self.send_probe_response,'SNIFF')
        self.add_transition('SNIFF','AuthReq',self.send_auth_response,'AUTH')
        self.add_transition('SNIFF','AssocReq',self.install_send_assoc_response,'ASSOC')
        self.add_transition('SNIFF','ReassocReq',self.install_send_reassoc_response,'ASSOC')
        self.add_transition('SNIFF','DisassocReq',None,'SNIFF')
        self.add_transition('SNIFF','DeauthReq',None,'SNIFF')
        self.add_transition('AUTH','ProbeReq',self.send_probe_response,'AUTH')
        self.add_transition('AUTH','AuthReq',self.send_auth_response,'AUTH')
        self.add_transition('AUTH','AssocReq',self.install_send_assoc_response,'ASSOC')
        self.add_transition('AUTH','ReassocReq',self.install_send_reassoc_response,'ASSOC')
        self.add_transition('ASSOC','ProbeReq',self.send_probe_response,'ASSOC')
        self.add_transition('ASSOC','AuthReq',self.send_auth_response,'ASSOC')
        self.add_transition('ASSOC','AssocReq',self.reinstall_send_assoc_response,'ASSOC')
        self.add_transition('ASSOC','ReassocReq',self.reinstall_send_reassoc_response,'ASSOC')        
        self.add_transition('ASSOC','DisassocReq',self.uninstall, 'NONE')
        self.add_transition('AUTH','DisassocReq',self.uninstall, 'NONE')
        self.add_transition('ASSOC','DeauthReq',self.uninstall, 'NONE')        
        self.add_transition('AUTH','DeauthReq',self.uninstall, 'NONE')        
        self.add_transition('ASSOC','HostTimeout',self.uninstall, 'NONE')

    def send_probe_response(self, *args):        
        pass

    def send_auth_response(self, *args):
        pass

    def send_assoc_response(self, *args):
        pass

    def reinstall_send_probe_response(self, *args):
        pass

    def reinstall_send_auth_response(self, *args):
        pass

    def reinstall_send_assoc_response(self, *args):
        pass



class PersonalAP(EventMixin, DefaultWiFiFSM):
    def __init__(self, station):
        DefaultWiFiFSM.__init__(self)
        self.ssid = SERVING_SSID
        self.sta = station
        self.virtualap = None
        
    def handle_probe_request(self, event):
        '''
        ProbeRequest can include several things, such as : 
        - monitoring a client, 
        - deciding whether to serve a client or not,
        - reserving a vbssid (or use an existing one) for this client
        - decide which channel to serve the user from
        - decide which AP to serve the client from

        Upon receiving a probe request from an unknown client we add it 
        to our station list in SNIFF state.
        
        We then need to decide if we reply to it and if so from which AP.
        For now the rule is simple : we reply only when the request is valid (ie. to
        SERVING_BSSID or broadcast), and we make sure that there is a single running AP :)
        A few strategies would be :
        - Assign the client to the AP that first reported a ProbeReq, and do all the association process
        through it.
        - Assign the client to the first AP above an SNR threshold, and have a way to fallback 
        in case the good threshold cannot be met.
        - Wait to hear a few ProbeReqs from this guy, and select which AP to use
        - Include channel selection on the previous.

        If we decide to process the request, we update the last_seen timer and pass the input
        to the Association FSM for this station ( more details on that at the sniff_to_reserve transition ).
        '''
        pass

    def handle_auth_request(self, event):
        pass

    def handle_assoc_request(self, event):
        pass

    def handle_reassoc_request(self, event):
        pass

    def handle_disassoc_request(self, event):
        pass

    def handle_deauth_request(self, event):
        pass

class PersonalDefaultBandSteeringAP(PersonalAP):
    '''Personal AP that supports client-driven association only at 5GHz.
    '''
    def __init__(self, station):
        PersonalAP.__init__(self, station)

    def handle_probe_request(self, event):
        # check if this is a valid probe-req to process (broadcast and SSID-check).
        # In the default WiFi case there is a direct RadioAP <-> VirtualAP relationship.
        # Send a ProbeResponse from that.
        if (self.is_valid_probe_request(event)):
            self.sta.last_seen = time.time()
            new_state = self.processFSM(self.sta.state, 'ProbeReq', event)
            log_fsm.debug("%012x : %s -> %s (ProbeReq, vbssid:%012x dpid:%012x)" % 
                          (self.sta.addr, self.sta.state, new_state, event.radioap.virtual_aps.values()[0].vbssid, 
                           event.radioap.parent_phyap.dpid))

    def handle_auth_request(self, event):
        if self.is_valid_auth_request(event, self.sta):
            self.sta.last_seen = time.time()
            new_state = self.processFSM(self.sta.state, 'AuthReq', event)
            log_fsm.debug("%012x : %s -> %s (AuthReq, vbssid:%012x dpid:%012x)" % 
                          (self.sta.addr, self.sta.state, new_state, event.virtualap.vbssid, event.virtualap.get_dpid()))
            self.sta.state = new_state

    def handle_assoc_request(self, event):
        if self.is_valid_assoc_request(event, self.sta) and self.is_valid_assoc_params(event, self.sta):
            self.sta.params = event.params
            self.sta.last_seen = time.time()
            new_state = self.processFSM(self.sta.state, 'AssocReq', event)
            log_fsm.debug("%012x : %s -> %s (AssocReq, vbssid:%012x dpid:%012x)" % 
                          (self.sta.addr, self.sta.state, new_state, event.virtualap.vbssid, event.virtualap.get_dpid()))
            self.sta.state = new_state
        else:
            log.warning("invalid assoc request from %012x (%012x,%012x)" % (self.sta.addr,event.virtualap.get_dpid(),event.virtualap.vbssid))

    def handle_reassoc_request(self, event):
        if self.is_valid_assoc_request(event, self.sta) and self.is_valid_assoc_params(event, self.sta):
            self.sta.params = event.params
            self.sta.last_seen = time.time()
            new_state = self.processFSM(self.sta.state, 'ReassocReq', event)
            log_fsm.debug("%012x : %s -> %s (ReassocReq, vbssid:%012x dpid:%012x)" % 
                          (self.sta.addr, self.sta.state, new_state, event.virtualap.vbssid, 
                           event.virtualap.parent_radioap.parent_phyap.dpid))
            self.sta.state = new_state
        else:
            log.warning("invalid reassoc request from %012x (%012x,%012x)" % 
                        (self.sta.addr,event.virtualap.get_dpid(), event.virtualap.vbssid))

    def handle_disassoc_request(self, event):
        if self.is_valid_disassoc_request(event, self.sta):
            old_state = sta.state
            new_state = self.processFSM(self.sta.state, 'DisassocReq', self.sta)
            log_fsm.debug("%012x : %s -> %s (DisassocReq, dpid:%012x,reason:%x)" %
                          (event.src_addr, old_state, new_state, event.virtualap.get_dpid(), event.reason))
        else:
            log.warning("invalid disassoc request from %x" % event.src_addr)

    def handle_deauth_request(self, event):
        if self.is_valid_deauth_request(event, self.sta):
            old_state = self.sta.state
            new_state = self.processFSM(self.sta.state, 'DeauthReq', self.sta)
            log_fsm.debug("%012x : %s -> %s (DeauthReq, dpid:%012x,reason:%x)" %
                          (event.src_addr, old_state, new_state, event.virtualap.get_dpid(), event.reason))
        else:
            log.warning("invalid deauth request from %x" % event.src_addr)

    def handle_host_timeout(self, event):
        log_fsm.debug("%012x : %s -> NONE (HostTimeout, dpid:%012x, packets:%d, bytes:%d,secs:%d)" % 
                      (self.sta.addr, self.sta.state, phy_ap.dpid, event.packets, event.bytes,event.dur))
        self.uninstall()

    def uninstall(self):
        if (self.virtualap):
            radioap = self.virtualap.parent_radioap
            phy_ap = radioap.parent_phyap
            authenticator = phy_ap.authenticator
            # delete backhaul switch entry
            authenticator.del_station_flow(self.sta.addr, phy_ap.dpid)
            # delete radio AP state
            radioap.del_station(self.sta.addr)
            # delete OpenFlow AP entry
            phy_ap._del_simple_flow(WAN_PORT, mac_dst = EthAddr("%012x" % self.sta.addr))

    def send_probe_response(self, event):
        # we have a single VAP installed on this interface, just send it there.
        event.radioap.virtual_aps.values()[0].send_probe_response(self.sta.addr, self.ssid)

    def send_auth_response(self, event):
        event.virtualap.send_auth_response(self.sta.addr)

    def install_send_assoc_response(self, event, reassoc=False):
        '''Install this personal AP in the infrastructure.
        Since VAP is already installed at the AP this means :
        - Add OpenFlow entry in backhaul switch.
        - Add OpenFlow entry in Access Point.
        - Add station state to the RadioAP.'''
        self.virtualap = event.virtualap
        radioap = self.virtualap.parent_radioap
        phy_ap = radioap.parent_phyap
        authenticator = phy_ap.authenticator
        # Add downlink flow at the AP.
        phy_ap._set_simple_flow(WAN_PORT,[radioap.wlan_port],mac_dst = EthAddr("%012x" % self.sta.addr), priority=2)
        # Add station state to the Radio AP.
        radioap.add_station(self.sta.addr, self.virtualap.vbssid,
                            self.sta.params, self.sta.aid)
        phy_ap.authenticator.set_station_flow(self.sta.addr, phy_ap.dpid)
        if reassoc == False:
            self.virtualap.send_assoc_response(self.sta.addr, self.sta.params, self.sta.aid)
        else:
            self.virtualap.send_reassoc_response(self.sta.addr, self.sta.params, self.sta.aid)

    def reinstall_send_assoc_response(self, event, reassoc=False):
        '''Check if we change Virtual AP. If we do:
        - Remove the state from the old radio AP first.
        - Remove OpenFlow entry from Access Point.
        - Remove OpenFlow entry from Backhaul Switch.
        '''
        if (self.virtualap) and (self.virtualap.vbssid != event.virtualap.vbssid):
            radioap = self.virtualap.parent_radioap
            phy_ap = radioap.parent_phyap
            authenticator = phy_ap.authenticator
            # delete backhaul switch entry
            authenticator.del_station_flow(self.sta.addr, phy_ap.dpid)
            # delete radio AP state
            radioap.del_station(self.sta.addr)
            # delete OpenFlow AP entry
            phy_ap._del_simple_flow(WAN_PORT, mac_dst = self.sta.addr)
        self.install_send_assoc_response(event, reassoc=reassoc)

    def install_send_reassoc_response(self, event):
        self.install_send_assoc_response(event, reassoc=True)

    def reinstall_send_reassoc_response(self, event):
        self.reinstall_send_assoc_response(reassoc=True)

    def is_valid_probe_request(self, event):
        '''
        Checks if a sniffed probe request is for us.
        '''
        # Just do an SSID-checking for the default WiFi case.
        # Also make sure it comes at the 5GHz band
        return (((event.ssid == SERVING_SSID) or (event.ssid == '') or (event.ssid == None)) and 
                (event.radioap.is_band_2GHZ() == False))
    
    def is_valid_auth_request(self, event, sta):
        return True

    def is_valid_assoc_request(self, event, sta):
        return True

    def is_valid_disassoc_request(self, event, sta):
        '''
        Checks if a sniffed disassoc request is for us. We accept at the first AP it came from.
        '''
        return (event.virtualap == self.virtualap)

    def is_valid_deauth_request(self, event, sta):
        '''
        Checks if a sniffed deauth request is for us. We accept at the first AP it came from.
        '''
        return (event.virtualap == self.virtualap)

    def is_valid_assoc_params(self, event, sta):
        '''
        Checks if the station asking to associate supports 40MHz, short GI and short slot.
        '''
        radioap = event.virtualap.parent_radioap
        if ((event.params.capabilities & radioap.capa_mask == radioap.capa_exp) and 
            (event.params.ht_capabilities) and (event.params.ht_capabilities['ht_capab_info'] & radioap.ht_capa_mask == radioap.ht_capa_exp)):
            return True
        else:
            log.error("Station with unexpected capabilities : %x (capab:%04x ht_capab:%04x)" % (self.sta.addr, event.params.capabilities, event.params.ht_capabilities['ht_capab_info']))
            return False

class VirtualAP(object):
    '''This is a VirtualAP instance.
    It's characterized by a VBSSID and it's placed on a RadioAP,
    from where it inherits its physical properties.
    '''
    def __init__(self, vbssid = None, parent_radioap = None):
        self.vbssid = vbssid
        self.parent_radioap = parent_radioap
        self.personal_aps = []
        
    def get_dpid(self):
        if self.parent_radioap:
            return self.parent_radioap.parent_phyap.dpid
        else:
            return None

    def send_probe_response(self, src_addr, ssid):
        log.debug("Sending Probe Response to %x" % src_addr)
        pkt_str = generate_probe_response(self.vbssid, ssid, src_addr, self.parent_radioap.current_channel, 
                                          self.parent_radioap.capabilities, 
                                          self.parent_radioap.ht_capabilities_info)
        self.send_packet_out(pkt_str)

    def send_auth_response(self, src_addr):
        log.debug("Sending Auth Response to %x" % src_addr)
        packet_str = generate_auth_response(self.vbssid, src_addr, self.parent_radioap.current_channel)
        self.send_packet_out(packet_str)

    def send_assoc_response(self, src_addr, params, sta_aid):
        log.debug("Sending Assoc Response to %x" % src_addr)
        packet_str = generate_assoc_response(self.vbssid, src_addr, params, self.parent_radioap.current_channel,
                                             self.parent_radioap.capabilities, 
                                             self.parent_radioap.ht_capabilities_info,sta_aid)
        self.send_packet_out(packet_str)

    def send_reassoc_response(self, src_addr, params, sta_aid):
        log.debug("Sending ReAssoc Response to %x" % src_addr)
        packet_str = generate_assoc_response(self.vbssid, src_addr, params, self.parent_radioap.current_channel,
                                             self.parent_radioap.capabilities, 
                                             self.parent_radioap.ht_capabilities_info,sta_aid, reassoc=True)
        self.send_packet_out(packet_str)

    def send_packet_out(self,msg_raw):
        self.parent_radioap.send_packet_out(msg_raw)

class PhyAP(EventMixin):
    '''
    This is the physical WiFi Switch.
    '''
    _eventMixin_events = set([ProbeRequest, AuthRequest, AssocRequest, ReassocRequest, AddStation, RemoveStation, 
                              DeauthRequest, DisassocRequest, ActionEvent,
                              AddVBeacon,DelVBeacon])
    
    def __init__(self, connection, transparent, dpid = None, is_blacklisted = False, whitelisted_stas = None, 
                 authenticator = None, phase_out=None):
        log.debug("Setting up PhyAP %012x" % dpid)
        EventMixin.__init__(self)
        self.connection = connection
        self.transparent = transparent
        self.dpid = dpid
        self.is_blacklisted = is_blacklisted
        self.whitelisted_stas = whitelisted_stas
        self.clients = []
        self.mon_ports = [WLAN_2_GHZ_MON_PORT, WLAN_5_GHZ_MON_PORT]
        self.phase_out = phase_out
        self.authenticator = authenticator
        
        if self.connection:
            self.listeners = connection.addListeners(self)
            # Setup default behavior
            # Traffic form WLAN <-> WAN
            # Broadcast traffic from WAN goes to both ports (the rest of the traffic through dst-based MAC
            # on client add.
            # Allow in-band connections to the AP from the WAN port
            # This assumes that the connection is direct and there is no NAT/FlowVisor in between, as 
            # we detect the AP's address through the OF connection.
            # Monitor port goes directly to the controller...        
            self._set_simple_flow(self.radioap_2GHz.wlan_port ,[WAN_PORT])
            self._set_simple_flow(self.radioap_5GHz.wlan_port ,[WAN_PORT])
            self._set_simple_flow(WAN_PORT, [self.radioap_2GHz.wlan_port, self.radio5GHz.wlan_port], 
                                  mac_dst=EthAddr("ffffffffffff"), priority=2)
            self._set_simple_flow(WAN_PORT,[of.OFPP_NORMAL],priority=3,ip_dst=connection.sock.getpeername()[0])
            self._set_simple_flow(of.OFPP_LOCAL,[WAN_PORT], priority=3,ip_src=connection.sock.getpeername()[0])
            # Allow arp packets with the AP's local IP address as destination.
            self._set_simple_flow(WAN_PORT, [of.OFPP_NORMAL],priority=3,dl_type=0x0806,ip_dst=connection.sock.getpeername()[0],nw_proto = 1)
            self._set_simple_flow(of.OFPP_LOCAL, [WAN_PORT],priority=3,dl_type=0x0806,ip_src=connection.sock.getpeername()[0],nw_proto = 2)

            # send a few more bytes in to capture all WiFi Header.
            self.connection.send(of.ofp_set_config(miss_send_len=1024))        
            
        self.radioap_2GHz =  RadioAP(channel = BEHOP_CHANNELS_2GHZ[self.dpid],
                                     intf = "wlan0",
                                     parent_phyap = self)
        self.radioap_5GHz =  RadioAP(channel = BEHOP_CHANNELS_5GHZ[self.dpid],
                                     intf = "wlan1",
                                     parent_phyap = self)


    def update_connection(self, connection):
        '''
        OVS occasionally restarts and the new connection pop-ups before the previous
        one disappearing. In that case, do not create a new AP, just update the connection
        information.
        '''
        if self.connection:
            self.connection.removeListeners(self.listeners)
        self.connection = connection
        self.listeners = self.connection.addListeners(self)
        # we also need to re-add flows as the switch will start from a clean-state.
        self._set_simple_flow(self.radioap_2GHz.wlan_port ,[WAN_PORT])
        self._set_simple_flow(self.radioap_5GHz.wlan_port ,[WAN_PORT])
        self._set_simple_flow(WAN_PORT, [self.radioap_2GHz.wlan_port, self.radioap_5GHz.wlan_port], 
                              mac_dst=EthAddr("ffffffffffff"), priority=2)
        self._set_simple_flow(WAN_PORT,[of.OFPP_NORMAL],priority=3,ip_dst=connection.sock.getpeername()[0])
        self._set_simple_flow(of.OFPP_LOCAL,[WAN_PORT], priority=3,ip_src=connection.sock.getpeername()[0])
        # Allow arp packets with the AP's local IP address as destination.
        self._set_simple_flow(WAN_PORT, [of.OFPP_NORMAL],priority=3,dl_type=0x0806,ip_dst=connection.sock.getpeername()[0],nw_proto = 1)
        self._set_simple_flow(of.OFPP_LOCAL, [WAN_PORT],priority=3,dl_type=0x0806,ip_src=connection.sock.getpeername()[0],nw_proto = 2)

        # send a few more bytes in to capture all WiFi Header.
        self.connection.send(of.ofp_set_config(miss_send_len=1024))        

    def get_dpid(self):
        return self.dpid

    def is_whitelisted(self, addr):
        if addr in self.whitelisted_stas:
            return True
        return False                              

    def _set_simple_flow(self,port_in, ports_out, priority=1,mac_src=None,mac_dst=None, 
                         ip_src=None, ip_dst=None,queue_id=None, dl_type=0x0800,nw_proto=None, idle_timeout=0):
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
        if nw_proto:
            msg.match.nw_proto = nw_proto
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


    def _handle_PacketIn(self, event):        
        # first log this packet for node's information
        if event.port in self.mon_ports:
            log_packet(event.parsed, event.dpid, event.port)

        if ((self.is_blacklisted) or (event.port not in self.mon_ports) or (self.phase_out[0])):
            return
        packet = event.parsed
        rdtap = dpkt.radiotap.Radiotap(packet.raw)
        rd_len = rdtap.length >> 8
        if rdtap.version != 0 or rd_len != 34: # or 18 on the pi's...
            #print "unrecognized rdtap header - ignore... (%d, %d)" % (rdtap.version, rd_len)
            return
        if rdtap.ant_sig_present:
            snr = rdtap.ant_sig.db - (-90)
        else:
            snr = 0
        try:
            ie = dpkt.ieee80211.IEEE80211(packet.raw[rd_len:])
        except NeedData:
            #log.debug("Cannot debug packet...")
            return
        # try to get an impacket version of the packet.
        try:
            im_radiotap = rdtap_decoder.decode(packet.raw)
            snr = im_radiotap.get_dBm_ant_signal() - (-90)
            im_pkt = dot11.Dot11(aBuffer=packet.raw[rd_len:], FCS_at_end=False)
        except Exception as e:
            log.error("Impacket conversion failed.")
            log.error(e)
            return
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_BEACON):
            return

        # react only to messages by whitelisted stations.
        if (ie.type == dpkt.ieee80211.MGMT_TYPE):
            src_addr = int(binascii.hexlify(ie.mgmt.src), 16)
            if  (not self.is_whitelisted(src_addr)):
                self.log_blacklisted_sta_packet(ie, event)
                return


        # get the radio that we took the reply from
        # Probe Requests are destined to the radio interface.
        # The rest (auth,(re)assoc,disassoc,deauth are destined to a VAP.
        # for the rest we just don't care.
        radioap = self.radioap_2GHz if event.port == WLAN_2_GHZ_MON_PORT else self.radioap_5GHz
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_PROBE_REQ):
            self.raiseEvent(ProbeRequest(radioap, int(binascii.hexlify(ie.mgmt.src),16), snr, ie.ssid.data))
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and (ie.subtype == dpkt.ieee80211.M_AUTH or
                                                     ie.subtype == dpkt.ieee80211.M_ASSOC_REQ or
                                                     ie.subtype == dpkt.ieee80211.M_REASSOC_REQ or
                                                     ie.subtype == dpkt.ieee80211.M_DISASSOC or
                                                     ie.subtype == dpkt.ieee80211.M_DEAUTH)):
            src = int(binascii.hexlify(ie.mgmt.src),16)
            vbssid = int(binascii.hexlify(ie.mgmt.bssid),16)
            vap = radioap.get_virtual_ap(vbssid)
            if vap == None:
                return

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_AUTH):
            # Auth requests are destined to a virtual-ap interface.
            self.raiseEvent(AuthRequest(vap, src, vbssid, snr))
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_ASSOC_REQ):
            params = WifiStaParams(packet.raw[rd_len:])
            self.raiseEvent(AssocRequest(vap, src, vbssid, snr, params))

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_REASSOC_REQ):
            params = WifiStaParams(packet.raw[rd_len:], reassoc=True)
            self.raiseEvent(ReassocRequest(vap,src ,vbssid, snr, params))
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_DISASSOC):
            self.raiseEvent(DisassocRequest(vap,src,vbssid,ie.diassoc.reason))
            log.debug("Disassoc with status code %x" % ie.diassoc.reason)

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_DEAUTH):
            self.raiseEvent(DeauthRequest(vap, src, vbssid,ie.deauth.reason))

    def log_blacklisted_sta_packet(self, ie, event):
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_AUTH):
            log.debug("%012x : UNHANDLED -> UNHANDLED (AuthReq,dst:%012x,bssid:%012x,dpid:%012x)" % 
                          (int(binascii.hexlify(ie.mgmt.src),16),int(binascii.hexlify(ie.mgmt.dst),16),
                           int(binascii.hexlify(ie.mgmt.bssid),16),event.dpid))
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_ASSOC_REQ):
            log.debug("%012x : UNHANDLED -> UNHANDLED (AssocReq,dst:%012x,bssid:%012x,dpid:%012x)" % 
                          (int(binascii.hexlify(ie.mgmt.src),16),int(binascii.hexlify(ie.mgmt.dst),16),
                           int(binascii.hexlify(ie.mgmt.bssid),16),event.dpid))

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_REASSOC_REQ):
            log.debug("%012x : UNHANDLED -> UNHANDLED (ReAssocReq,dst:%012x,dpid:%012x,bssid:%012x)" % 
                          (int(binascii.hexlify(ie.mgmt.src),16),int(binascii.hexlify(ie.mgmt.dst),16),
                           int(binascii.hexlify(ie.mgmt.bssid),16),event.dpid))
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_DISASSOC):
            log.debug("%012x : UNHANDLED -> UNHANDLED (DisAssocReq,dst:%012x,bssid:%012x,dpid:%012x)" % 
                          (int(binascii.hexlify(ie.mgmt.src),16),int(binascii.hexlify(ie.mgmt.dst),16),
                           int(binascii.hexlify(ie.mgmt.bssid),16),event.dpid))
            log.debug("Disassoc with status code %x" % ie.diassoc.reason)

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_DEAUTH):
            log.debug("%012x : UNHANDLED -> UNHANDLED (DeauthReq,dst:%012x,bssid:%012x,dpid:%012x)" % 
                          (int(binascii.hexlify(ie.mgmt.src),16),int(binascii.hexlify(ie.mgmt.dst),16),
                           int(binascii.hexlify(ie.mgmt.bssid),16),event.dpid))        
            log.debug("Deauth with status code %x" % ie.deauth.reason)
       
    def send_packet_out(self, msg_raw, port):
        msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
        msg.actions.append(of.ofp_action_output(port = port))
        msg.data = msg_raw
        self.connection.send(msg)

