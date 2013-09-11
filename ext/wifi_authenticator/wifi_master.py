"""
A WiFi Authenticator.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time
from pox.lib.recoco import Timer

import dpkt, binascii
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

class RemoveStation(Event):
    def __init__(self, dpid, src_addr):
        Event.__init__(self)
        self.dpid = dpid
        self.src_addr = src_addr

class MoveStation(Event):
    def __init__(self, addr, old_dpid, new_dpid):
        Event.__init__(self)
        self.addr = addr
        self.old_dpid = old_dpid
        self.new_dpid = new_dpid

class Station(object):
    def __init__(self, addr):
        self.addr = addr # mac address of station
        self.dpid = None # dpid to which the station is assigned.
        self.vbssid = None # assigned vbssid        
        self.last_seen = time.time()
        self.state = 'SNIFF'

class WifiAuthenticateSwitch(EventMixin):
    _eventMixin_events = set([ProbeRequest, AuthRequest, AssocRequest, AddStation, RemoveStation])
    
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
    '''
    This is the main class for WifiAuthentication. It keeps track of all APs
    on a AP-map and spawns a WifiAuthenticateSwitch for each AP.
    * Monitors raw 80211 management events and generates Probe/Auth/Assoc Responses
    * Manages virtual-BSSID (vbssid)
    * Decides where to place a station and sets appropriate state to the related AP.
    * Talks to the Information Base (IB) and decides whether to move a station and where.
    * Monitors stations, checks for timeouts, etc.
    '''
    _eventMixin_events = set([AddStation, RemoveStation])

    def __init__(self, transparent):
        '''
        Setup vbssid map and placeholders for APs and stations.
        '''
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
        '''
        Setup timer for stations timeout.
        '''
        if self.timer : self.timer.cancel()
        self.timer = Timer(1, self.check_timeout_events, recurring=True)

    def delete_station(self, sta):
        '''
        Deletes a station from the AP-map, removes state from the AP itself, 
        and frees reserved vbssid.
        '''
        if self.vbssid_map.has_key(sta.addr):
            # this might not work...
            self.raiseEvent(RemoveStation(sta.dpid, sta.addr))
            del self.vbssid_map[sta.addr]
            self.vbssid_pool.append(sta.vbssid)
        del self.stations[sta.addr]

    def check_timeout_events(self):
        '''
        Periodically checks if stations are alive and if not remove associated state.
        As we have to soft-reserve VBSSID during probe-responses, this has to run frequently
        to ensure that we don't run out of VBSSID soon.
        @TODO : Check the state of the station and vbssid before removing.
        @TODO : Probably generate related deauth/disassoc messages from here (?)
        '''
        log.debug("Remaining VBSSIDs : %d" % len(self.vbssid_pool))
        now = time.time()
        for sta in self.stations.values():
            if now - sta.last_seen > ASSOC_TIMEOUT and sta.state != "ASSOC":
                self.delete_station(sta)
        
        
    def is_valid_probe_request(self, event):
        '''
        Checks if a sniffed association request is for us.
        '''
        #log.debug("Got request for SSID %s" % event.ssid)
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
        log.debug("%s %s %s %s" % (event.bssid, sta.vbssid, event.dpid, sta.dpid))
        return ((event.bssid == sta.vbssid) and (event.dpid == sta.dpid))

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
        wifi_ap = WifiAuthenticateSwitch(event.connection, self.transparent)
        wifi_ap.addListeners(self)
        self.aps[event.dpid] = wifi_ap

    def _handle_ConnectionDown(self, event):
        '''
        Remove stations associated with this switch.
        '''
        log.debug("Connection terminated : %s" % (event.connection))
        log.debug("Removing AP state and associated stations...")
        for sta in self.stations.values():
            if sta.dpid == event.dpid:
                self.delete_station(sta)
        del self.aps[event.dpid]
        
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
        if event.src_addr not in self.stations.keys():
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

    def _handle_MoveStation(self, event):
        '''Moving a station from one AP to another.'''        
        log.debug("Received Request to move station %x from %x to %x" % (event.addr, event.old_dpid,
                                                                         event.new_dpid))
        # Check that the node is currently associated to an AP.
        if event.addr not in self.stations.keys() or self.stations[event.addr].state != 'ASSOC' or self.stations[event.addr].dpid  != event.old_dpid:                
            log.debug("Only associated nodes can move...")

        # else we can move the station across the two APs.
        sta = self.stations[event.addr]
        params = {}
        self.raiseEvent(RemoveStation(event.old_dpid, sta.addr))
        self.raiseEvent(AddStation(event.new_dpid, sta.addr, sta.vbssid, params))
        sta.dpid = event.new_dpid
                       
    def sniff_to_reserve(self, event):
        '''
        When we are about to handle the first probe request from a station we move the station
        to the RESERVE state. This means that we already reserved a vbssid for it and we have 
        decided on which AP to client the client from. We update this information on our stations map
        and set the respective set at the AP.
        '''
        addr = event.src_addr
        dpid = event.dpid
        self.stations[addr].vbssid = self.get_vbssid_for_host(addr)
        self.stations[addr].dpid = dpid
        self.sendProbeResponse(event)
        self.raiseEvent(AddStation(event.dpid, event.src_addr, self.stations[addr].vbssid, {}))
        log.debug("Sending Probe Response to %x" % addr)

    def auth_to_assoc(self, event):
        '''
        Plain association response for now.
        '''
        addr = event.src_addr
        vbssid = self.stations[addr].vbssid
        self.sendAssocResponse(event)
        log.debug("Sending Assoc Response to %x" % addr)
        log.info("Adding %s to AP %s with VBSSID %x" % (event.src_addr, event.dpid, vbssid))
        #self.raiseEvent(AddStation(event.dpid, event.src_addr, vbssid, event.params))
                
    def sendProbeResponse(self, event):
        vbssid = self.stations[event.src_addr].vbssid
        ssid = SERVING_SSID
        pkt_str = generate_probe_response(vbssid, ssid, event.src_addr)
        self.aps[event.dpid].send_packet_out(pkt_str)

    def sendAuthResponse(self, event):
        vbssid = self.stations[event.src_addr].vbssid
        ssid = SERVING_SSID

        packet_str = generate_auth_response(vbssid, event.src_addr)
        self.aps[event.dpid].send_packet_out(packet_str)

        # Some drivers also wait to hear a beacon before they move from authentication to association...
        # this shouldn't happen here... 
        packet_str = generate_beacon(vbssid, ssid)
        self.aps[event.dpid].send_packet_out(packet_str)

    def sendAssocResponse(self, event):
        vbssid = self.stations[event.src_addr].vbssid
        packet_str = generate_assoc_response(vbssid, event.src_addr)
        self.aps[event.dpid].send_packet_out(packet_str)

def launch( transparent=False):
    core.registerNew(WifiAuthenticator, str_to_bool(transparent))
            
