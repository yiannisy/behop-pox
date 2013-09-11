"""
A WiFi Authenticator.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
import random
from pox.lib.recoco import Timer

import dpkt, binascii
import impacket.dot11 as dot11
from pox.lib.revent import *
from wifi_helper import *

from dpkt import NeedData

import hashlib

log = core.getLogger("WifiMaster")

WAN_PORT  = 1 # ethernet port
MON_PORT  = 2 # monitor port where we expect mgmt packets from.
WLAN_PORT = 3 # wireless port
SERVING_SSID = 'malakas'
ASSOC_TIMEOUT = 5


RADIOTAP_STR = '\x00\x00\x18\x00\x6e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xa8\x81\x02\x00\x00\x00\x00\x00\x00\x00'
PROBE_RESPONSE_STR = '\x50\x00\x3a\x01\xc8\x3a\x35\xcf\xcc\x37\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\xc0\x37\xb0\xdb\x28\x05\x00\x00\x00\x00\x64\x00\x01\x04\x00\x06\x70\x69\x2d\x61\x70\x31\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x03\x01\x01\x2a\x01\x06\x32\x04\x30\x48\x60\x6c\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00' #\x28\xf3\xe0\x3a'

BEACON_STR = '\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x00\x26\xcb\x18\x6a\x30\x00\x26\xcb\x18\x6a\x30\xa0\xd0\x77\x09\x32\x03\x8f\x00\x00\x00\x66\x00\x31\x04\x00\x04\x43\x41\x45\x4e\x01\x08\x82\x84\x8b\x0c\x12\x96\x18\x24\x03\x01\x01\x05\x04\x00\x01\x00\x00\x07\x06\x55\x53\x20\x01\x0b\x1a\x0b\x05\x00\x00\x6e\x00\x00\x2a\x01\x02\x2d\x1a\x6e\x18\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x30\x14\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x04\x01\x00\x00\x0f\xac\x01\x28\x00\x32\x04\x30\x48\x60\x6c\x36\x03\x51\x63\x03\x3d\x16\x01\x00\x05\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x85\x1e\x05\x00\x8f\x00\x0f\x00\xff\x03\x59\x00\x63\x73\x65\x2d\x33\x39\x31\x32\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x36\x96\x06\x00\x40\x96\x00\x14\x00\xdd\x18\x00\x50\xf2\x02\x01\x01\x80\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\xdd\x06\x00\x40\x96\x01\x01\x04\xdd\x05\x00\x40\x96\x03\x05\xdd\x05\x00\x40\x96\x0b\x09\xdd\x08\x00\x40\x96\x13\x01\x00\x34\x01\xdd\x05\x00\x40\x96\x14\x05'

_PROBE_RESPONSE_STR = "\x00\x00\x1a\x00\x2f\x48\x00\x00\x93\x44\x1f\x90\x4e\x4e\x00\xd2\x10\x02\x6c\x09\xa0\x00\xdb\x01\x00\x00\x50\x00\x3a\x01\xc8\x3a\x35\xcf\xcc\x37\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\xc0\x37\xb0\xdb\x28\x05\x00\x00\x00\x00\x64\x00\x01\x04\x00\x06\x70\x69\x2d\x61\x70\x31\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x03\x01\x01\x2a\x01\x06\x32\x04\x30\x48\x60\x6c\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\x28\xf3\xe0\x3a"

AUTH_REPLY_STR = "\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xd9\x01\x00\x00\xb0\x00\x3a\x01\xc8\x3a\x35\xcf\xcc\x37\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x70\x3a\x00\x00\x02\x00\x00\x00"

ASSOC_REPLY_STR="\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xd7\x01\x00\x00\x10\x00\x3a\x01\xc8\x3a\x35\xcf\xcc\x37\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x80\x3a\x01\x04\x00\x00\x01\xc0\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x32\x04\x30\x48\x60\x6c\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"


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
    '''
    def __init__(self, dpid, src_addr, bssid, snr, params):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.bssid = bssid
        self.snr = snr
        self.params = params

class AddStation(Event):
    def __init__(self, dpid, src_addr, vbssid, params):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr
        self.vbssid = vbssid
        self.params = params

class Station(object):
    def __init__(self, addr):
        self.addr = addr # mac address of station
        self.dpid = None # dpid to which the station is assigned.
        self.vbssid = None # assigned vbssid        
        self.last_seen = time.time()
        self.state = 'SNIFF'

class WifiAuthenticateSwitch(EventMixin):
    _eventMixin_events = set([ProbeRequest, AuthRequest, AssocRequest, AddStation])
    
    def __init__(self, connection, transparent):
        EventMixin.__init__(self)
        self.connection = connection
        self.transparent = transparent

        
        connection.addListeners(self)
        # Setup default behavior
        # Switch traffic between WAN <-> WLAN port
        # Allow in-band connections to the AP from the WAN port
        # This assumes that the connection is direct and there is no NAT/FlowVisor in between, as 
        # we detect the AP's address through the OF connection.
        # Monitor port goes directly to the controller...
        self._set_simple_flow(WAN_PORT,WLAN_PORT)
        self._set_simple_flow(WLAN_PORT,WAN_PORT)
        self._set_simple_flow(WAN_PORT,of.OFPP_NORMAL,priority=2,ip_dst=connection.sock.getpeername()[0])
        self._set_simple_flow(of.OFPP_LOCAL,of.OFPP_NORMAL, priority=2,ip_src=connection.sock.getpeername()[0])
                              

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
        if event.port != MON_PORT:
            return

        packet = event.parsed
        rdtap = dpkt.radiotap.Radiotap(packet.raw)
        rd_len = rdtap.length >> 8
        if rdtap.version != 0 or rd_len != 34: # or 18 on the pi's...
            #print "unrecognized rdtap header - ignore... (%d, %d)" % (rdtap.version, rd_len)
            return

        try:
            ie = dpkt.ieee80211.IEEE80211(packet.raw[rd_len:])
        except NeedData:
            #log.debug("Cannot debug packet...")
            return

        #log.debug("received packet %x %x from %s" % (ie.type, ie.subtype, binascii.hexlify(ie.mgmt.src)))
        
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_BEACON):
            return

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_PROBE_REQ):
            #log.debug("%s -> %s (%s)" % (binascii.hexlify(ie.mgmt.src), ie.ssid, ie.ssid.data))
            self.raiseEvent(ProbeRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src),16), 0, ie.ssid.data))

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_AUTH):
            self.raiseEvent(AuthRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src),16), int(binascii.hexlify(ie.mgmt.bssid),16), 0))
            #self.send_packet_out(AUTH_REPLY_STR)
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_ASSOC_REQ):
            params = WifiStaParams(packet.raw)
            self.raiseEvent(AssocRequest(event.dpid, int(binascii.hexlify(ie.mgmt.src),16), int(binascii.hexlify(ie.mgmt.bssid),16), 0, params))

        #if (ie.type == 0 and ie.subtype != 8):
        #    print "Received %x from %s" % (ie.subtype, binascii.hexlify(ie.mgmt.src))
       

    def send_packet_out(self, msg_raw):
        msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
        msg.actions.append(of.ofp_action_output(port = MON_PORT))
        msg.data = msg_raw
        self.connection.send(msg)


class WifiAuthenticator(EventMixin, AssociationFSM):
    _eventMixin_events = set([AddStation])

    def __init__(self, transparent):
        EventMixin.__init__(self)
        AssociationFSM.__init__(self)
        core.openflow.addListeners(self)
        self.transparent = transparent
        self.aps = {}
        self.vbssid_base = 0x020000000000
        self.vbssid_backup = 0x060000000000
        self.vbssid_pool = [self.vbssid_base | (1 << i) for i in range(0,40)]
        self.vbssid_map = {}
        self.stations = {}
        self.timer = None
        self.set_timer()

    def set_timer(self):
        if self.timer : self.timer.cancel()
        self.timer = Timer(1, self.check_timeout_events, recurring=True)

    def check_timeout_events(self):
        log.debug("Remaining VBSSIDs : %d" % len(self.vbssid_pool))
        now = time.time()
        for sta in self.stations.values():
            if now - sta.last_seen > ASSOC_TIMEOUT and sta.state != "ASSOC":
                if self.vbssid_map.has_key(sta.addr):
                    del self.vbssid_map[sta.addr]
                    self.vbssid_pool.append(sta.vbssid)
                del self.stations[sta.addr]
        
        
    def is_valid_probe_request(self, event):
        #log.debug("Got request for SSID %s" % event.ssid)
        return ((event.ssid == SERVING_SSID) or (event.ssid == '') or (event.ssid == None))

    def is_valid_auth_request(self, event, sta):
        return ((event.bssid == sta.vbssid) and (event.dpid == sta.dpid))
        
    def is_valid_assoc_request(self, event, sta):
        log.debug("%s %s %s %s" % (event.bssid, sta.vbssid, event.dpid, sta.dpid))
        return ((event.bssid == sta.vbssid) and (event.dpid == sta.dpid))

    def get_vbssid_for_host(self, src_addr):
        #check if this node has already a vbssid assigned.
        #if not, pick-up the first one from the pool and assign it to this host.
        #make sure to return the vbssid to the pool when the node leaves/disassociates.
        #As this needs to happen early (probe-request/response) we should free-up the
        #nodes that don't follow-up with auth/assoc request.
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
        log.debug("Connection %s" % (event.connection))
        wifi_ap = WifiAuthenticateSwitch(event.connection, self.transparent)
        wifi_ap.addListeners(self)
        self.aps[event.dpid] = wifi_ap

    def _handle_ProbeRequest(self, event):
        #log.debug("Got a probe request event from %s!!" % dpid_to_str(event.dpid))

        if event.src_addr in self.stations.keys():
            sta = self.stations[event.src_addr]
        else:
            self.stations[event.src_addr] = Station(event.src_addr)
            sta = self.stations[event.src_addr]

        # check if this is a valid probe-req to process.
        # this needs more sophistication : we could sniff on irrelevant probe-reqs
        # or we might have to decide between multiple dpids...
        if self.is_valid_probe_request(event):
            sta.last_seen = time.time()
            sta.state = self.processFSM(sta.state,'ProbeReq', event)

    def _handle_AuthRequest(self, event):        
        log.info("Got an auth request from %x!!" % event.src_addr)
        if event.src_addr in self.stations.keys():
            sta = self.stations[event.src_addr]
        else:
            self.stations[event.src_addr] = Station(event.src_addr)
            sta = self.stations[event.src_addr]

        if self.is_valid_auth_request(event, sta):
            sta.last_seen = time.time()
            sta.state = self.processFSM(sta.state, 'AuthReq', event)

    def _handle_AssocRequest(self, event):
        log.info("Got an assoc request event from %x!!" % event.src_addr)
        if event.src_addr in self.stations.keys():
            sta = self.stations[event.src_addr]
        else:
            self.stations[event.src_addr] = Station(event.src_addr)
            sta = self.stations[event.src_addr]

        if self.is_valid_assoc_request(event, sta):
            sta.last_seen = time.time()
            sta.state = self.processFSM(sta.state, 'AssocReq', event)
        else:
            log.debug("invalid assoc request")


    def sniff_to_reserve(self, event):
        addr = event.src_addr
        dpid = event.dpid
        self.stations[addr].vbssid = self.get_vbssid_for_host(addr)
        self.stations[addr].dpid = dpid
        self.sendProbeResponse(event)
        log.debug("Sending Probe Response to %x" % addr)

    def auth_to_assoc(self, event):
        addr = event.src_addr
        vbssid = self.stations[addr].vbssid
        self.sendAssocResponse(event)
        log.debug("Sending Assoc Response to %x" % addr)
        log.info("Adding %s to AP %s with VBSSID %x" % (event.src_addr, event.dpid, vbssid))
        self.raiseEvent(AddStation(event.dpid, event.src_addr, vbssid, event.params))
                
    def sendProbeResponse(self, event):
        vbssid = self.stations[event.src_addr].vbssid
        ssid = SERVING_SSID

        rdtap =  dpkt.radiotap.Radiotap(RADIOTAP_STR)
        
        #if event.src_addr != "c83a35cfcc37" and event.src_addr != "00215c53c6e9":
        #    return

        #dst = [int(x,16) for x in [event.src_addr[0:2], event.src_addr[2:4], event.src_addr[4:6],
        #                           event.src_addr[6:8], event.src_addr[8:10], event.src_addr[10:]]]
        dst = mac_to_array(event.src_addr)
        bssid = mac_to_array(vbssid)

        # Frame Control
        frameCtrl = dot11.Dot11(FCS_at_end = False)
        frameCtrl.set_version(0)
        frameCtrl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_RESPONSE)
        # Frame Control Flags
        frameCtrl.set_fromDS(0)
        frameCtrl.set_toDS(0)
        frameCtrl.set_moreFrag(0)
        frameCtrl.set_retry(0)
        frameCtrl.set_powerManagement(0)
        frameCtrl.set_moreData(0)
        frameCtrl.set_protectedFrame(0)
        frameCtrl.set_order(0)
 
        # Management Frame
        sequence = random.randint(0, 4096)
        mngtFrame = dot11.Dot11ManagementFrame()
        mngtFrame.set_duration(0)
        mngtFrame.set_destination_address(dst)
        mngtFrame.set_source_address(bssid)
        mngtFrame.set_bssid(bssid)
        mngtFrame.set_fragment_number(0)
        mngtFrame.set_sequence_number(sequence)
 
        # Beacon Frame
        baconFrame = dot11.Dot11ManagementProbeResponse()
        baconFrame.set_ssid(ssid)
        baconFrame.set_capabilities(0x0401)
        baconFrame.set_beacon_interval(0x0064)
        baconFrame.set_supported_rates([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x18, 0x30, 0x48])
        baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x12\x24\x60\x6c")
 
        mngtFrame.contains(baconFrame)
        frameCtrl.contains(mngtFrame)
 
        resp_str = frameCtrl.get_packet()
        #log.debug("length of pkt : %d" % len(resp_str))

        packet_str = RADIOTAP_STR + resp_str

        self.aps[event.dpid].send_packet_out(packet_str)


    def sendAuthResponse(self, event):
        vbssid = self.stations[event.src_addr].vbssid
        ssid = SERVING_SSID

        rdtap =  dpkt.radiotap.Radiotap(RADIOTAP_STR)
        
        #log.debug("%s, %s" % (ssid, bssid))
        dst = mac_to_array(event.src_addr)
        bssid = mac_to_array(vbssid)

        #log.debug(dst)
        #log.debug(event.src_addr)


        # Frame Control
        frameCtrl = dot11.Dot11(FCS_at_end = False)
        frameCtrl.set_version(0)
        frameCtrl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_AUTHENTICATION)
        # Frame Control Flags
        frameCtrl.set_fromDS(0)
        frameCtrl.set_toDS(0)
        frameCtrl.set_moreFrag(0)
        frameCtrl.set_retry(0)
        frameCtrl.set_powerManagement(0)
        frameCtrl.set_moreData(0)
        frameCtrl.set_protectedFrame(0)
        frameCtrl.set_order(0)
 
        # Management Frame
        sequence = random.randint(0, 4096)
        mngtFrame = dot11.Dot11ManagementFrame()
        mngtFrame.set_duration(0)
        mngtFrame.set_destination_address(dst)
        mngtFrame.set_source_address(bssid)
        mngtFrame.set_bssid(bssid)
        mngtFrame.set_fragment_number(0)
        mngtFrame.set_sequence_number(sequence)
 
        # Auth Reply Frame
        authFrame = dot11.Dot11ManagementAuthentication()
        authFrame.set_authentication_algorithm(0)
        authFrame.set_authentication_sequence(2)
        authFrame.set_authentication_status(0)
 
        mngtFrame.contains(authFrame)
        frameCtrl.contains(mngtFrame)
 
        resp_str = frameCtrl.get_packet()
        #log.debug("length of pkt : %d" % len(resp_str))

        packet_str = RADIOTAP_STR + resp_str

        self.aps[event.dpid].send_packet_out(packet_str)

        # Some drivers also wait to hear a beacon before they move from authentication to association...
        # this shouldn't happen here...
        # Frame Control
        frameCtrl = dot11.Dot11(FCS_at_end = False)
        frameCtrl.set_version(0)
        frameCtrl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_BEACON)
        # Frame Control Flags
        frameCtrl.set_fromDS(0)
        frameCtrl.set_toDS(0)
        frameCtrl.set_moreFrag(0)
        frameCtrl.set_retry(0)
        frameCtrl.set_powerManagement(0)
        frameCtrl.set_moreData(0)
        frameCtrl.set_protectedFrame(0)
        frameCtrl.set_order(0)
 
        # Management Frame
        sequence = random.randint(0, 4096)
        mngtFrame = dot11.Dot11ManagementFrame()
        mngtFrame.set_duration(0)
        mngtFrame.set_destination_address([0xff,0xff,0xff,0xff,0xff,0xff])
        mngtFrame.set_source_address(bssid)
        mngtFrame.set_bssid(bssid)
        mngtFrame.set_fragment_number(0)
        mngtFrame.set_sequence_number(sequence)
 
        # Beacon Frame
        baconFrame = dot11.Dot11ManagementProbeResponse()
        baconFrame.set_ssid(ssid)
        baconFrame.set_capabilities(0x0401)
        baconFrame.set_beacon_interval(0x0064)
        baconFrame.set_supported_rates([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x18, 0x30, 0x48])
        baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x12\x24\x60\x6c")
 
        mngtFrame.contains(baconFrame)
        frameCtrl.contains(mngtFrame)

        resp_str = frameCtrl.get_packet()
        #log.debug("length of pkt : %d" % len(resp_str))

        packet_str = RADIOTAP_STR + resp_str

        self.aps[event.dpid].send_packet_out(packet_str)


    def sendAssocResponse(self, event):
        vbssid = self.stations[event.src_addr].vbssid
        ssid = SERVING_SSID

        rdtap =  dpkt.radiotap.Radiotap(RADIOTAP_STR)
        
        #log.debug("%s, %s" % (ssid, bssid))
        dst = mac_to_array(event.src_addr)
        bssid = mac_to_array(vbssid)

        #log.debug(dst)
        #log.debug(event.src_addr)

        # Frame Control
        frameCtrl = dot11.Dot11(FCS_at_end = False)
        frameCtrl.set_version(0)
        frameCtrl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_ASSOCIATION_RESPONSE)
        # Frame Control Flags
        frameCtrl.set_fromDS(0)
        frameCtrl.set_toDS(0)
        frameCtrl.set_moreFrag(0)
        frameCtrl.set_retry(0)
        frameCtrl.set_powerManagement(0)
        frameCtrl.set_moreData(0)
        frameCtrl.set_protectedFrame(0)
        frameCtrl.set_order(0)
 
        # Management Frame
        sequence = random.randint(0, 4096)
        mngtFrame = dot11.Dot11ManagementFrame()
        mngtFrame.set_duration(0)
        mngtFrame.set_destination_address(dst)
        mngtFrame.set_source_address(bssid)
        mngtFrame.set_bssid(bssid)
        mngtFrame.set_fragment_number(0)
        mngtFrame.set_sequence_number(sequence)
 
        # Assoc Response Frame
        assocFrame = dot11.Dot11ManagementAssociationResponse()
        assocFrame.set_capabilities(0x0401)
        assocFrame.set_status_code(0)
        assocFrame.set_association_id(0xc001)
        assocFrame.set_supported_rates([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x18, 0x30, 0x48])
        assocFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x12\x24\x60\x6c")

 
        mngtFrame.contains(assocFrame)
        frameCtrl.contains(mngtFrame)
 
        resp_str = frameCtrl.get_packet()
        #log.debug("length of pkt : %d" % len(resp_str))

        packet_str = RADIOTAP_STR + resp_str

        log.info("Sending Association Response to %x" % (event.src_addr))
        self.aps[event.dpid].send_packet_out(packet_str)

def launch( transparent=False):
    core.registerNew(WifiAuthenticator, str_to_bool(transparent))
            
