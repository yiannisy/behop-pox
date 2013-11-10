"""
A WiFi Authenticator.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str as mac_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.recoco import Timer
from ovsdb_msg import SnrSummary,AggService, AggBot
from pox.forwarding.l2_learning import LearningSwitch

import dpkt, binascii
from pox.lib.revent import *
from wifi_helper import *

from dpkt import NeedData
from pox.lib.addresses import EthAddr
from behop_config import *
from wifi_params import *

import hashlib

log = core.getLogger("WifiMessenger")
log_fsm = core.getLogger("WifiFSM")
log_mob = core.getLogger("WifiMobility")

all_stations = {}
all_aps = {}
phase_out = [False]


class ProbeRequest(Event):
    '''Event raised by an AP when a probe request is received.
    @dpid : the AP reporting the request
    @src_addr : host's address
    @snr: the snr of the packet
    '''
    def __init__(self, dpid, src_addr, snr, ssid):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.snr = snr
        self.ssid = ssid
    
class AuthRequest(Event):
    '''Event raised by an AP when a probe request is received.
    @dpid : the AP reporting the request
    @src_addr : host's address
    @bssid : the bssid for the authentication
    @snr: the snr of the packet
    '''
    def __init__(self, dpid, src_addr, bssid, snr):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.bssid = bssid
        self.snr = snr

class AssocRequest(Event):
    '''Event raised by an AP when a probe request is received.
    @dpid : the AP reporting the request
    @src_addr : host's address
    @bssid : the bssid for the assocation
    @snr: the snr of the packet
    @params : the Wifi params
    '''
    def __init__(self, dpid, src_addr, bssid, snr, params):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.bssid = bssid
        self.snr = snr
        self.params = params

class ReassocRequest(Event):
    '''Event raised by an AP when a probe request is received.
    @dpid : the AP reporting the request
    @src_addr : host's address
    @bssid : the bssid for the assocation
    @snr: the snr of the packet
    @params : the Wifi params
    '''
    def __init__(self, dpid, src_addr, bssid, snr, params):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.bssid = bssid
        self.snr = snr
        self.params = params


class DisassocRequest(Event):
    '''Event raised by an AP when a disassoc request is received.
    @dpid : the AP reporting the request.
    @src_addr : host's address
    @bssid : the bssid from which the disassoc is reported.
    '''
    def __init__(self, dpid, src_addr, bssid):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.bssid = bssid

    def __str__(self):
        return "dpid:%012x | src_addr:%012x | bssid:%012x" % (self.dpid, self.src_addr, self.bssid)

class DeauthRequest(Event):
    '''Event raised by an AP when a deauth request is received.
    @dpid : the AP reporting the request.
    @src_addr : host's address
    @bssid : the bssid from which the disassoc is reported.
    '''
    def __init__(self, dpid, src_addr, bssid):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.bssid = bssid

    def __str__(self):
        return "dpid:%012x | src_addr:%012x | bssid:%012x" % (self.dpid, self.src_addr, self.bssid)

class ActionEvent(Event):
    '''Event raised by an AP when it receives an action packet.
    @dpid : the AP reporting the request.
    @src_addr : host's address
    '''
    def __init__(self, dpid, src_addr, bssid):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.bssid = bssid


class HostTimeout(Event):
    '''Event raised by the backhaul switch when the downlink flow
    for a host timeouts.
    @dst_addr : The address of the host.
    @dpid : The dpid of the switch.
    '''
    def __init__(self, dpid, dst_addr, packets, bytes, dur):
        Event.__init__(self)
        self.dpid = dpid
        self.dst_addr = int(dst_addr.toStr(separator=''),16)
        self.packets = packets
        self.bytes = bytes
        self.dur = dur

class AddStation(Event):
    def __init__(self, dpid, intf, src_addr, vbssid, aid, params, ht_capa):
        Event.__init__(self)
        self.dpid = dpid
        self.intf = intf
        self.src_addr = src_addr
        self.vbssid = vbssid
        self.aid = aid
        self.params = params
        self.ht_capabilities_info = ht_capa

class RemoveStation(Event):
    def __init__(self, dpid, intf, src_addr):
        Event.__init__(self)
        self.dpid = dpid
        self.intf = intf
        self.src_addr = src_addr

class MoveStation(Event):
    def __init__(self, addr, old_dpid, new_dpid):
        Event.__init__(self)
        self.addr = addr
        self.old_dpid = old_dpid
        self.new_dpid = new_dpid

class UpdateBssidmask(Event):
    def __init__(self, dpid, intf, bssidmask):
        Event.__init__(self)
        self.dpid = dpid
        self.intf = intf
        self.bssidmask = bssidmask

class Station(object):
    def __init__(self, addr):
        self.addr = addr # mac address of station
        self.dpid = None # dpid to which the station is assigned.
        self.vbssid = None # assigned vbssid        
        self.last_seen = time.time() # last heard from the AP.
        self.last_snr = 0 # SNR of last packet as reported form the dpid.
        self.state = 'SNIFF'
        log_fsm.debug("%012x : NONE -> %s" % (self.addr, self.state))

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
        # all ports should go to the uplink to start with.
        for ap, ap_port in self.topo.items():
            self._set_simple_flow(ap_port, [BACKHAUL_UPLINK])
            self._set_simple_flow(BACKHAUL_UPLINK, [ap_port], mac_dst=EthAddr("%012x" % ap), priority=2)
        # add flow for broadcast
        self._set_simple_flow(BACKHAUL_UPLINK, self.topo.values(), mac_dst=EthAddr("ffffffffffff"), priority=2)
        self._set_simple_flow(BACKHAUL_UPLINK, [], priority=1)

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

    def _set_simple_flow(self,port_in, ports_out, priority=1,mac_dst=None, ip_src=None, ip_dst=None,queue_id=None, idle_timeout=0):
        msg = of.ofp_flow_mod()
        msg.idle_timeout=idle_timeout
        msg.flags = of.OFPFF_SEND_FLOW_REM
        msg.priority = priority
        msg.match.in_port = port_in
        if (mac_dst):
            msg.match.dl_dst = mac_dst
        if (ip_dst or ip_src):
            msg.match.dl_type = 0x0800
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

class WifiAuthenticateSwitch(EventMixin):
    _eventMixin_events = set([ProbeRequest, AuthRequest, AssocRequest, ReassocRequest, AddStation, RemoveStation, 
                              DeauthRequest, DisassocRequest, ActionEvent])
    
    def __init__(self, connection, transparent, is_blacklisted = False, whitelisted_stas = None, channel = 11):
        EventMixin.__init__(self)
        self.connection = connection
        self.transparent = transparent
        self.is_blacklisted = is_blacklisted
        self.whitelisted_stas = whitelisted_stas
        self.current_channel = channel
        self.clients = []
        self.set_capabilities()

        connection.addListeners(self)
        # Setup default behavior
        # Switch traffic between WAN <-> WLAN port
        # Allow in-band connections to the AP from the WAN port
        # This assumes that the connection is direct and there is no NAT/FlowVisor in between, as 
        # we detect the AP's address through the OF connection.
        # Monitor port goes directly to the controller...        
        self._set_simple_flow(WAN_PORT,self.wlan_port)
        self._set_simple_flow(self.wlan_port,WAN_PORT)
        self._set_simple_flow(WAN_PORT,of.OFPP_NORMAL,priority=2,ip_dst=connection.sock.getpeername()[0])
        self._set_simple_flow(of.OFPP_LOCAL,of.OFPP_NORMAL, priority=2,ip_src=connection.sock.getpeername()[0])

        # send a few more bytes in to capture all WiFi Header.
        self.connection.send(of.ofp_set_config(miss_send_len=256))        



    def is_whitelisted(self, addr):
        if addr in self.whitelisted_stas:
            return True
        return False

    def is_band_2GHZ(self):
        if self.current_channel <= WLAN_2_GHZ_CHANNEL_MAX:
            return True
        return False
                              
    def set_capabilities(self):
        '''
        Set the capabilities advertised by the AP according to the channel.
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



    def _set_simple_flow(self,port_in,port_out, priority=1,ip_src=None, ip_dst=None,queue_id=None):
        msg = of.ofp_flow_mod()
        msg.idle_timeout=0
        msg.priority = priority
        msg.match.in_port = port_in
        if (ip_dst or ip_src):
            msg.match.dl_type = 0x0800
            if (ip_dst):
                msg.match.nw_dst = ip_dst
            if (ip_src):
                msg.match_nw_src = ip_src
        msg.actions.append(of.ofp_action_output(port = port_out))
        self.connection.send(msg)

    def _handle_PacketIn(self, event):        
        # first log this packet for node's information
        log_packet(event.parsed, event.dpid)

        if ((self.is_blacklisted) or (event.port != self.mon_port) or (phase_out[0])):
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
                return

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_PROBE_REQ):
            self.raiseEvent(ProbeRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src),16), snr, ie.ssid.data))

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_AUTH):
            self.raiseEvent(AuthRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src),16), int(binascii.hexlify(ie.mgmt.bssid),16), snr))
            #self.send_packet_out(AUTH_REPLY_STR)
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_ASSOC_REQ):
            params = WifiStaParams(packet.raw[rd_len:])
            self.raiseEvent(AssocRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src),16), int(binascii.hexlify(ie.mgmt.bssid),16), snr, params))

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_REASSOC_REQ):
            log.debug("Ignoring Reassociation Request...")
            #params = WifiStaParams(packet.raw[rd_len:])
            #self.raiseEvent(ReassocRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src),16), int(binascii.hexlify(ie.mgmt.bssid),16), snr, params))

            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_DISASSOC):
            self.raiseEvent(DisassocRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src), 16), 
                                            int(binascii.hexlify(ie.mgmt.bssid), 16)))

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_DEAUTH):
            self.raiseEvent(DeauthRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src), 16), 
                                            int(binascii.hexlify(ie.mgmt.bssid), 16)))

                            

        #if (ie.type == 0 and ie.subtype != 8):
        #    print "Received %x from %s" % (ie.subtype, binascii.hexlify(ie.mgmt.src))
       
    def send_packet_out(self, msg_raw):
        msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
        msg.actions.append(of.ofp_action_output(port = self.mon_port))
        msg.data = msg_raw
        self.connection.send(msg)


class WifiAuthenticator(EventMixin, AssociationFSM):
    '''
    This is the main class for WifiAuthentication. It keeps track of all APs
    on a AP-map and spawns a WifiAuthenticateSwitch for each AP.
    * Monitors raw 80211 management events and generates Probe/Auth/Assoc Responses
    * Manages virtual-BSSID (vbssid)
    * Decides where to place a station and sets appropriate state to the related AP.
    * Talks to the Information Base (IB) and decides whether to move a station and where.
    * Monitors stations, checks for timeouts, etc.
    '''
    _eventMixin_events = set([AddStation, RemoveStation, MoveStation, UpdateBssidmask, SnrSummary])

    def __init__(self, transparent):
        '''
        Setup vbssid map and placeholders for APs and stations.
        '''
        EventMixin.__init__(self)
        AssociationFSM.__init__(self)
        self.agg_msnger = AggBot(core.MessengerNexus.get_channel("MON_IB"), extra={'parent':self})
        core.openflow.addListeners(self)
        #core.openflow_discovery.addListenerByName("LinkEvent", self._handle_LinkEvent)
        self.transparent = transparent
        self.bh_switch = None
        self.vbssid_base = 0x020000000000
        self.vbssid_backup = 0x060000000000
        self.vbssid_pool = [self.vbssid_base | (1 << i) for i in range(VBSSID_RANGE_MIN,VBSSID_RANGE_MAX)]
        self.vbssid_map = {}
        self.timer = None
        self.bw_timer = None
        self.set_timer()
        self.next_aid = 0x0001
        self.blacklisted_aps = []
        self.whitelisted_stas = []
        if USE_BLACKLIST == 1:
            self.blacklisted_aps = self.load_blacklisted_aps()
        if USE_WHITELIST == 1:
            self.whitelisted_stas = self.load_whitelisted_stas()

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
            log.info("%012x" % ap)
        return b_aps

    def load_whitelisted_stas(self):
        w_stas = []
        f = open(WHITELIST_FNAME,'r')
        for line in f.readlines():
            if line.startswith('#'):
                continue
            w_stas.append(int(line.rstrip(), 16))
        f.close()
        log.info("Updated List of Whitelisted STAs:")
        for sta in w_stas:
            log.info("%012x" % sta)
        return w_stas

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
        self.timer = Timer(5, self.check_timeout_events, recurring=True)
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
            del self.vbssid_map[sta.addr]
            self.vbssid_pool.append(sta.vbssid)
        dpid = sta.dpid
        del all_stations[sta.addr]
        if update_bssidmask:
            self.update_bssidmask(dpid)

    def check_timeout_events(self):
        '''
        Periodically checks if stations are alive and if not remove associated state.
        As we have to soft-reserve VBSSID during probe-responses, this has to run frequently
        to ensure that we don't run out of VBSSID soon.
        @TODO : Check the state of the station and vbssid before removing.
        @TODO : Probably generate related deauth/disassoc messages from here (?)
        '''
        now = time.time()
        _affected_aps = []
        for sta in all_stations.values():
            if now - sta.last_seen > ASSOC_TIMEOUT and sta.state != "ASSOC":
                _affected_aps.append(sta.dpid)
                log_fsm.debug("%012x : %s -> %s (ResTimeout)" % (sta.addr, sta.state, "NONE"))
                self.delete_station(sta, update_bssidmask=False)

        _affected_aps = set(_affected_aps)

        # update the bssidmask of the affected APs
        # group per AP to avoid multiple updates to the AP.
        for ap in _affected_aps:
            if ap:
                self.update_bssidmask(ap)

    def is_valid_probe_request(self, event):
        '''
        Checks if a sniffed probe request is for us.
        '''
        #if the station is already assigned to an AP, we respond only to probe requests from this AP.
        sta = all_stations[event.src_addr]
        if (sta.dpid != None and (sta.dpid != event.dpid)):
            return False
        return ((event.ssid == SERVING_SSID) or (event.ssid == '') or (event.ssid == None))

    def is_valid_auth_request(self, event, sta):
        '''
        Checks if a sniffed authentication request is for us and comes from the expected AP.
        '''
        return ((event.bssid == sta.vbssid) and (event.dpid == sta.dpid))
        
    def is_valid_assoc_request(self, event, sta):
        '''
        Checks if a sniffed association request is for us and comes from the expected AP.
        '''
        #log.debug("%s %s %s %s" % (event.bssid, sta.vbssid, event.dpid, sta.dpid))
        return ((event.bssid == sta.vbssid) and (event.dpid == sta.dpid))

    def is_valid_disassoc_request(self, event, sta):
        '''
        Checks if a sniffed disassoc request is for us. We accept at the first AP it came from.
        '''
        return (event.bssid == sta.vbssid)

    def is_valid_deauth_request(self, event, sta):
        '''
        Checks if a sniffed deauth request is for us. We accept at the first AP it came from.
        '''
        return (event.bssid == sta.vbssid)

    def is_valid_action_event(self, event, sta):
        '''
        Checks if the station is associated, the request comes from the assigned AP,
        and is destined to the sta's vbssid.
        '''
        return ((event.dpid == sta.dpid) and (event.bssid == sta.vbssid) and (sta.state == 'ASSOC'))

    def is_valid_assoc_params(self, event, sta):
        '''
        Checks if the station asking to associate supports 40MHz, short GI and short slot.
        '''
        wifi_ap = all_aps[sta.dpid]
        if ((event.params.capabilities & wifi_ap.capa_mask == wifi_ap.capa_exp) and (event.params.ht_capabilities) and (event.params.ht_capabilities['ht_capab_info'] & wifi_ap.ht_capa_mask == wifi_ap.ht_capa_exp)):
            return True
        else:
            log.error("Station with unexpected capabilities : %x (capab:%04x ht_capab:%04x)" % (sta.addr, event.params.capabilities, event.params.ht_capabilities['ht_capab_info']))
            return False

    def check_sta_switch(self, event, sta):
        '''
        Checks if we need to switch AP for this sta.
        '''
        # if sta is not assigned to an AP will grab it by default, no need to interfere here.
        if (sta.dpid == None):
            return
        if (sta.dpid != event.dpid):
            # if we are here we got a packet from an AP different from the one that the station
            # is currently assigned. We ignore this unless one of the following happens:
            # i) the packet comes with a much better SNR that the sta's AP.
            # ii) it's been a long time since we last heard from the last AP.
            if (event.snr - sta.last_snr > 15 and sta.last_snr < 20) or (time.time() - sta.last_seen > 5e6):
                log_mob.info("Triggering Change for station %x" % sta.addr)
                if (sta.state != 'SNIFF'):
                    # state already installed in AP - need to move.
                    self.move_station(sta.addr, sta.dpid, event.dpid)
                sta.dpid = event.dpid

    def check_sta_move(self, sta, sta_summary):
        '''
        Checks whether we should move a station from an AP to another.
        Works only for stations who are already associated.
        '''
        cur_dpid_str = '%012x' % sta.dpid
        cur_dpid = sta.dpid
        # Monitor IB should know about this dpid, but sometimes is out-of-sync...
        if cur_dpid_str not in sta_summary.keys():
            return
        cur_snr = sta_summary[cur_dpid_str][0]
        max_dpid, max_snr = max([(int(dpid,16),sta_summary[dpid][0]) for dpid in sta_summary.keys()], key=lambda sta:sta[1])
        
        log_str = ' '.join(["%s->%d" % (dpid,sta_summary[dpid][0]) for dpid in sta_summary.keys()])
        log_mob.debug("Station %012x : Cur_SNR : %d (%012x) | Max_SNR : %d (%012x) Details : %s" % (sta.addr, cur_snr, cur_dpid, max_snr, max_dpid, log_str))
        if cur_snr > GOOD_SNR_THRESHOLD:
            return
        if max_snr - cur_snr > SNR_SWITCH_THRESHOLD:
            log_mob.debug("Triggering Change for station %012x (%012x -> %012x)" % (sta.addr, cur_dpid, max_dpid))
            self.move_station(sta.addr, cur_dpid, max_dpid)

    def get_next_aid(self):
        '''
        Gives the next association-id (aid). Rotate among available aids.
        @TODO : ensure that there are no duplicate AIDs at the same AP.
        (probably need to maintain unique AID for each station...)
        '''
        cur_id = self.next_aid
        if self.next_aid == 0x3fff:
            self.next_aid = 0x0001
        else:
            self.next_aid += 1
        return cur_id
                        
    def get_vbssid_for_host(self, src_addr):
        '''
        checks if this node has already a vbssid assigned.
        if not, pick-up the first one from the pool and assign it to this host.
        make sure to return the vbssid to the pool when the node leaves/disassociates.
        As this needs to happen early (probe-request/response) we should free-up the
        nodes that don't follow-up with auth/assoc request.
        '''
        if self.vbssid_map.has_key(src_addr):
            vbssid = self.vbssid_map[src_addr]
        else:
            if(len(self.vbssid_pool) > 0):
                vbssid = self.vbssid_pool[0]
                self.vbssid_map[src_addr] = vbssid
                del self.vbssid_pool[0]
            else:
                log.warn("Running out of VBSSID - giving backup vbssid for node %s" % src_addr)
                vbssid = self.vbssid_backup
        return vbssid

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
            try:
                channel = BEHOP_CHANNELS[event.dpid]
            except:
                # no predefined channel for this AP---pick-up the default one.
                log.debug("no predefined channel for this AP---pick-up the default one.")
                channel = DEFAULT_BEHOP_CHANNEL
            wifi_ap = WifiAuthenticateSwitch(event.connection, self.transparent, self.is_blacklisted(event.dpid), self.whitelisted_stas, channel = channel)
            wifi_ap.addListeners(self)
            all_aps[event.dpid] = wifi_ap

    def _handle_ConnectionDown(self, event):
        '''
        Remove stations associated with this switch.
        '''
        log.debug("Connection terminated : %s" % (event.connection))
        if (event.dpid == BACKHAUL_SWITCH):
            log.debug("Removing Backhaul Switch...")
        else:
            log.debug("Removing AP state and associated stations...")
            for sta in all_stations.values():
                if sta.dpid == event.dpid:
                    self.delete_station(sta)
            del all_aps[event.dpid]

    def _handle_LinkEvent(self, event):
        if event.added == True:
            log.debug("Link added : %x:%d -> %x:%d" % (event.link.dpid1, event.link.port1,
                                                       event.link.dpid2, event.link.port2))
        
    def _handle_ProbeRequest(self, event):
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
        if event.src_addr not in all_stations.keys():
            all_stations[event.src_addr] = Station(event.src_addr)

        sta = all_stations[event.src_addr]

        self.check_sta_switch(event, sta)
            
        # check if this is a valid probe-req to process.
        # this needs more sophistication : we could sniff on irrelevant probe-reqs
        # or we might have to decide between multiple dpids...            
        if (self.is_valid_probe_request(event)):
            sta.last_seen = time.time()
            sta.snr = event.snr
            new_state = self.processFSM(sta.state,'ProbeReq', event)
            log_fsm.debug("%012x : %s -> %s (ProbeReq,vbssid:%012x dpid:%012x)" % 
                          (sta.addr, sta.state, new_state, sta.vbssid, sta.dpid))
            sta.state = new_state

    def _handle_AuthRequest(self, event):
        if event.src_addr in all_stations.keys():
            sta = all_stations[event.src_addr]
        else:
            all_stations[event.src_addr] = Station(event.src_addr)
            sta = all_stations[event.src_addr]

        self.check_sta_switch(event, sta)

        if self.is_valid_auth_request(event, sta):
            sta.last_seen = time.time()
            new_state = self.processFSM(sta.state, 'AuthReq', event)
            log_fsm.debug("%012x : %s -> %s (AuthReq, vbssid:%012x dpid:%012x)" % 
                          (sta.addr, sta.state, new_state, sta.vbssid, sta.dpid))
            sta.state = new_state

    def _handle_AssocRequest(self, event):
        if event.src_addr in all_stations.keys():
            sta = all_stations[event.src_addr]
        else:
            all_stations[event.src_addr] = Station(event.src_addr)
            sta = all_stations[event.src_addr]

        self.check_sta_switch(event, sta)

        if self.is_valid_assoc_request(event, sta) and self.is_valid_assoc_params(event, sta):
            sta.params = event.params
            sta.last_seen = time.time()
            new_state = self.processFSM(sta.state, 'AssocReq', event)
            log_fsm.debug("%012x : %s -> %s (AssocReq, vbssid:%012x dpid:%012x)" % 
                          (sta.addr, sta.state, new_state, sta.vbssid, sta.dpid))
            sta.state = new_state
        else:
            log.warning("invalid assoc request")

    def _handle_ReassocRequest(self, event):
        if event.src_addr in all_stations.keys():
            sta = all_stations[event.src_addr]
        else:
            all_stations[event.src_addr] = Station(event.src_addr)
            sta = all_stations[event.src_addr]

        self.check_sta_switch(event, sta)

        if self.is_valid_assoc_request(event, sta) and self.is_valid_assoc_params(event, sta):
            sta.params = event.params
            sta.last_seen = time.time()
            new_state = self.processFSM(sta.state, 'ReassocReq', event)
            log_fsm.debug("%012x : %s -> %s (ReassocReq, vbssid:%012x dpid:%012x)" % 
                          (sta.addr, sta.state, new_state, sta.vbssid, sta.dpid))
            sta.state = new_state
        else:
            log.warning("invalid reassoc request")


    def _handle_DisassocRequest(self, event):
        # we only care about stations already registered...
        if event.src_addr in all_stations.keys():
            sta = all_stations[event.src_addr]
        else:
            return

        if self.is_valid_disassoc_request(event, sta):
            old_state = sta.state
            new_state = self.processFSM(sta.state, 'DisassocReq', sta)
            log_fsm.debug("%012x : %s -> %s (DisassocReq, dpid:%012x)" %
                          (event.src_addr, old_state, new_state, event.dpid))
        else:
            log.warning("invalid disassoc request")

    def _handle_DeauthRequest(self, event):
        # we only care about stations already registered...
        if event.src_addr in all_stations.keys():
            sta = all_stations[event.src_addr]
        else:
            return

        if self.is_valid_deauth_request(event, sta):
            old_state = sta.state
            new_state = self.processFSM(sta.state, 'DeauthReq', sta)
            log_fsm.debug("%012x : %s -> %s (DeauthReq, dpid:%012x)" %
                          (event.src_addr, old_state, new_state, event.dpid))
        else:
            log.warning("invalid deauth request")

    def _handle_ActionEvent(self, event):
        log.debug("handling action")
        if event.src_addr in all_stations.keys():
            sta = all_stations[event.src_addr]
        else:
            return
        if self.is_valid_action_event(event, sta):
            log.debug("sending action")
            self.sendActionResponse(event)

    def _handle_MoveStation(self, event):
        '''Moving a station from one AP to another.'''        
        log_mob.debug("Received Request to move station %x from %x to %x" % (event.addr, event.old_dpid,
                                                                         event.new_dpid))
        # Check that the node is currently associated to an AP.
        if event.addr not in all_stations.keys() or all_stations[event.addr].state != 'ASSOC' or all_stations[event.addr].dpid  != event.old_dpid:                
            log_mob.debug("Only associated nodes can move...")

        # else we can move the station across the two APs.
        sta = all_stations[event.addr]
        params = {}
        self.removeStation(event.old_dpid, sta.addr)
        self.addStation(event.new_dpid, sta.addr)
        sta.dpid = event.new_dpid
        self.update_bssidmask(old_dpid)
        self.update_bssidmask(new_dpid)


    def move_station(self, addr, old_dpid, new_dpid):
        log_mob.debug("Received Request to move station %x from %x to %x" % (addr, old_dpid,
                                                                         new_dpid))
        # Check that the node is currently associated to an AP.
        if addr not in all_stations.keys() or all_stations[addr].state != 'ASSOC' or all_stations[addr].dpid  != old_dpid:                
            log_mob.debug("Only associated nodes can move...")

        # else we can move the station across the two APs.
        sta = all_stations[addr]
        params = {}
        self.removeStation(old_dpid, sta.addr)
        self.addStation(new_dpid, sta.addr)        
        sta.dpid = new_dpid
        self.update_bssidmask(old_dpid)
        self.update_bssidmask(new_dpid)

    def _handle_SnrSummary(self, event):
        for sta in all_stations.values():
            if sta.state == 'ASSOC':
                vbssid_str = "%012x" % sta.vbssid
                try:
                    sta_summary = event.summary[vbssid_str]
                except KeyError:
                    log.debug("sta %s not found in snr summary" % (vbssid_str))
                    continue
                self.check_sta_move(sta, sta_summary)

    def addStation(self, dpid, addr):
        '''
        Adds a station to a dpid. This means :
        * add a flow to the backhaul switch.
        * Add state to the AP.
        '''
        wifi_ap = all_aps[dpid]
        if self.bh_switch:
            self.bh_switch._set_simple_flow(BACKHAUL_UPLINK, [self.bh_switch.topo[dpid]], priority=2,
                                            mac_dst=EthAddr(mac_to_str(addr)), idle_timeout = DEFAULT_HOST_TIMEOUT)
        self.raiseEvent(AddStation(dpid, wifi_ap.intf, addr, all_stations[addr].vbssid,all_stations[addr].aid,all_stations[addr].params, wifi_ap.ht_capabilities_info))
        
    def removeStation(self, dpid, addr):
        wifi_ap = all_aps[dpid]
        if self.bh_switch:
            self.bh_switch._del_simple_flow(BACKHAUL_UPLINK,mac_dst=EthAddr(mac_to_str(addr)))
        self.raiseEvent(RemoveStation(dpid, wifi_ap.intf, addr))

    def update_bssidmask(self, dpid):
        wifi_ap = all_aps[dpid]
        bssidmask = 0xffffffffffff
        for sta in all_stations.values():
            if sta.dpid == dpid:
                bssidmask &= ~(sta.vbssid ^ BASE_HW_ADDRESS)
        self.raiseEvent(UpdateBssidmask(dpid, wifi_ap.intf, bssidmask))

    def _handle_HostTimeout(self, event):
        '''
        Remove the state for this host.
        '''
        if event.dst_addr in all_stations.keys():
            sta = all_stations[event.dst_addr]
        else:
            #nothing to do..
            return
        old_state = sta.state
        new_state = self.processFSM(sta.state, 'HostTimeout', sta)
        log_fsm.debug("%012x : %s -> %s (HostTimeout, dpid:%012x, packets:%d, bytes:%d,secs:%d)" % 
                      (event.dst_addr, old_state, new_state, event.dpid, event.packets, event.bytes,event.dur))

    def sniff_to_reserve(self, event):
        '''
        When we are about to handle the first probe request from a station we move the station
        to the RESERVE state. This means that we already reserved a vbssid for it and we have 
        decided on which AP to client the client from. We update this information on our stations map
        and set the respective set at the AP.
        '''
        addr = event.src_addr
        dpid = event.dpid
        all_stations[addr].vbssid = self.get_vbssid_for_host(addr)
        all_stations[addr].dpid = dpid
        all_stations[addr].last_snr = event.snr
        all_stations[addr].aid = self.get_next_aid()
        self.update_bssidmask(dpid)
        self.sendProbeResponse(event)

    def reinstallSendProbeResponse(self, event):
        self.update_bssidmask(event.dpid)
        self.sendProbeResponse(event)

    def reinstallSendAuthResponse(self, event):
        self.update_bssidmask(event.dpid)
        self.sendAuthResponse(event)

    def reinstallSendAssocResponse(self, event):
        self.update_bssidmask(event.dpid)
        self.addStation(event.dpid, event.src_addr)
        self.sendAssocResponse(event)

    def reinstallSendReassocResponse(self, event):
        self.update_bssidmask(event.dpid)
        self.addStation(event.dpid, event.src_addr)
        self.sendReassocResponse(event)


    def auth_to_assoc(self, event):
        '''
        Plain association response for now.
        '''
        addr = event.src_addr
        vbssid = all_stations[addr].vbssid
        self.update_bssidmask(event.dpid)
        self.addStation(event.dpid, event.src_addr)
        self.sendAssocResponse(event)
                        
    def sendProbeResponse(self, event):
        log.debug("Sending Probe Response to %x" % event.src_addr)
        vbssid = all_stations[event.src_addr].vbssid
        wifi_ap = all_aps[event.dpid]
        ssid = SERVING_SSID
        pkt_str = generate_probe_response(vbssid, ssid, event.src_addr, wifi_ap.current_channel, 
                                          wifi_ap.capabilities, wifi_ap.ht_capabilities_info)
        all_aps[event.dpid].send_packet_out(pkt_str)

    def sendAuthResponse(self, event):
        log.debug("Sending Auth Response to %x" % event.src_addr)
        vbssid = all_stations[event.src_addr].vbssid
        wifi_ap = all_aps[event.dpid]
        ssid = SERVING_SSID

        packet_str = generate_auth_response(vbssid, event.src_addr, wifi_ap.current_channel)
        all_aps[event.dpid].send_packet_out(packet_str)

        # Some drivers also wait to hear a beacon before they move from authentication to association...
        # this shouldn't happen here... 
        packet_str = generate_beacon(vbssid, ssid, wifi_ap.current_channel,
                                     wifi_ap.capabilities, wifi_ap.ht_capabilities_info)
        all_aps[event.dpid].send_packet_out(packet_str)

    def sendAssocResponse(self, event):
        log.debug("Sending Assoc Response to %x" % event.src_addr)
        sta = all_stations[event.src_addr]
        wifi_ap = all_aps[event.dpid]
        vbssid = sta.vbssid
        packet_str = generate_assoc_response(vbssid, event.src_addr, event.params, wifi_ap.current_channel,
                                             wifi_ap.capabilities, wifi_ap.ht_capabilities_info,sta.aid)
        all_aps[event.dpid].send_packet_out(packet_str)

    def sendReassocResponse(self, event):
        log.debug("Sending ReAssoc Response to %x" % event.src_addr)
        sta = all_stations[event.src_addr]
        wifi_ap = all_aps[event.dpid]
        vbssid = sta.vbssid
        packet_str = generate_assoc_response(vbssid, event.src_addr, event.params, wifi_ap.current_channel,
                                             wifi_ap.capabilities, wifi_ap.ht_capabilities_info,sta.aid, 
                                             reassoc=True)
        all_aps[event.dpid].send_packet_out(packet_str)

        
    def sendActionResponse(self, event):
        log.debug("Sending Action Response to %x" % event.src_addr)
        vbssid = all_stations[event.src_addr].vbssid
        wifi_ap = all_aps[event.dpid]
        packet_str = generate_action_response(vbssid, event.src_addr, wifi_ap.current_channel)
        all_aps[event.dpid].send_packet_out(packet_str)

def launch( transparent=False):
    core.Interactive.variables['behop_stations'] = all_stations
    core.Interactive.variables['behop_aps'] = all_aps
    core.Interactive.variables['behop_phase_out'] = phase_out
    core.registerNew(WifiAuthenticator, str_to_bool(transparent))
