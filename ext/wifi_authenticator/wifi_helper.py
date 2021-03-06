import impacket.dot11 as dot11
from impacket.ImpactDecoder import RadioTapDecoder
import dpkt
import binascii
import struct
import random
from pox.core import core
from behop_config import *
from wifi_params import *
from math import log10
import sys
from pox.lib.revent import *

RADIOTAP_STR = '\x00\x00\x18\x00\x6e\x48\x00\x00\x00\x0c\x3c\x14\x40\x01\xa8\x81\x02\x00\x00\x00\x00\x00\x00\x00'
HT_CAPA_STR_BASE = "\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
COUNTRY_STR = "\x55\x53\x20\x24\x04\x11\x95\x05\x1e\x00"



HOMENETS_OUI = "020000" # needs to be better defined.
BEACON_INTERVAL = 100
DEFAULT_CHANNEL = 11

log = core.getLogger("WifiMaster")
log_fsm = core.getLogger("WifiFSM")
log_ltsta = core.getLogger("WifiLTSTA")
rdtap_decoder = RadioTapDecoder()

def log_packet(packet, dpid, port):
    try:
        im_radiotap = rdtap_decoder.decode(packet.raw)
    except:
        log_ltsta.error("cannot decode radiotap information (%x:%d)" % (dpid,port))
        return
    try:
        snr = im_radiotap.get_dBm_ant_signal() - (-90)
        noise = im_radiotap.get_dBm_ant_noise()
    except:
        log_ltsta.error("cannot get SNR/noise information (%x:%d, %s)." % (dpid,port, sys.exc_info()[0]))

        return

    try:
        channel = im_radiotap.get_channel()[0]
        if channel < WLAN_2_GHZ_FREQ_MAX :
            band = '2.4GHz'
        else:
            band = '5GHz'
    except:
        log_ltsta.error("cannot get channel information (%x:%d)." % (dpid,port))
        return
    try:
        _dot11 = im_radiotap.child()
        mgmt_base = _dot11.child()
        addr = byte_array_to_hex_str(mgmt_base.get_source_address())
        type_subtype = _dot11.get_type_n_subtype()
    except:
        log_ltsta.error("cannot obtain mgmt packet.")
        return
    if type_subtype == dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST:
        log_ltsta.debug("PROBE_REQ|%x|%s|%d|%s|%d" % (dpid,addr,channel,band,snr))
        
def log_probereq(packet):
    try:
        im_radiotap = rdtap_decoder.decode(packet.raw)
        channel = im_radiotap.get_channel()[0]
    except:
        log_ltsta.error("Cannot obtain channel information")
        return
    try:
        _dot11 = im_radiotap.child()
        mgmt_base = _dot11.child()
        addr = byte_array_to_hex_str(mgmt_base.get_source_address())
    except:
        log_ltsta.error("cannot obtain source mac address")
        return
    log_ltsta.debug("PROBE_REQ|%s|%d" % (addr,channel))

def log_assocreq(packet, params):
    addr = "000000000000"
    channel = 0
    supp_rates = ()
    ext_rates = ()
    capa = 0
    ht_capa = 0
    if (params):
        addr = params.addr
        supp_rates = params.supp_rates
        ext_rates = params.ext_rates
        capa = params.capabilities
        if params.ht_capabilities:
            ht_capa = params.ht_capabilities['ht_capab_info']
    try:
        im_radiotap = rdtap_decoder.decode(packet.raw)
        channel = im_radiotap.get_channel()[0]
    except:
        log_ltsta.error("Cannot obtain channel information")
    try:
        log_ltsta.debug("ASSOC_REQ|%s|%d|%s|%s|%04x|%04x" % (byte_array_to_hex_str(addr),channel,
                                                   supp_rates,ext_rates,
                                                   capa,ht_capa['ht_capab_info']))
    except:
        log_ltsta.error("Cannot dump node capabilities---skipping...")

def mac_to_array(mac):
    s_mac = mac
    if (not isinstance(mac, str)):
        s_mac = "%012x" % mac
    a_mac = [int(x,16) for x in [s_mac[0:2], s_mac[2:4], s_mac[4:6],
                                 s_mac[6:8], s_mac[8:10], s_mac[10:]]]
    return a_mac

def byte_array_to_hex_str(x):
    return ''.join(['%02x' % n for n in x])

def get_ht_capa_info(ht_capa_info_sta, own_capa_info):
    '''
    Combine capabilities of AP and station.
    based on hostapd_get_ht_capab .
    '''
    print "host came with capa : %x" % ht_capa_info_sta
    cap = ht_capa_info_sta
    cap &= own_capa_info | 0x030c
    #cap &= 0xfcff
    # awful way to get little-endian here (probably need to move this to sta-manager)
    _cap_1 = cap/256
    _cap_2 = cap % 256
    cap = _cap_2*256 + _cap_1
    print "host installed with capa : %x" % cap
    return cap

def generate_probe_response(vbssid, ssid, dst_addr, channel, capa, ht_capa):
    '''
    Generates probe response for the given (vbssid, ssid, dst_addr) tuple.
    '''
    dst = mac_to_array(dst_addr)
    bssid = mac_to_array(vbssid)

    # Radiotap Header
    radioCtrl = dot11.RadioTap(aBuffer = RADIOTAP_STR)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        channel_flags = 0x000a
        rate = 0x02
    else:
        channel_flags = 0x0140
        rate = 0x0c
    freq = CHANNEL_FREQS[channel]
    radioCtrl.set_rate(rate)
    radioCtrl.set_channel(freq,channel_flags)

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
    baconFrame.set_capabilities(capa)
    baconFrame.set_beacon_interval(BEACON_INTERVAL)
    baconFrame.set_ds_parameter_set(channel)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        baconFrame.set_supported_rates(WLAN_2_GHZ_SUPP_RATES)
        baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x30\x48\x60\x6c")
    else:
        baconFrame.set_supported_rates(WLAN_5_GHZ_SUPP_RATES)
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.ERP_INFO,"\x02")
    # Country Info
    baconFrame._set_element(7,COUNTRY_STR)
    # HT Capabilities
    ht_capa_info_str = struct.pack('H',ht_capa)
    ht_capa_rest_str = HT_CAPA_STR_BASE
    ht_capa_str = ht_capa_info_str + ht_capa_rest_str
    baconFrame._set_element(45,ht_capa_str)
    # HT info
    ht_info_ch_str = chr(channel)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        ht_info_oper_str = chr(0)
    else:
        ht_info_oper_str = chr(5)
    ht_info_str_rest = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ht_info_str = ht_info_ch_str + ht_info_oper_str + ht_info_str_rest
    baconFrame._set_element(61, ht_info_str)
    # Extended Capabilities
    ext_capab_str = "\x00\x00\x00\x00\x00\x00\x00\x40"
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXTENDED_CAPABILITIES, ext_capab_str)

    # Add WMM/QoS
    wmm_str = "\x02\x01\x01\x04\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"
    baconFrame.add_vendor_specific("\x00\x50\xf2",wmm_str)

    
    mngtFrame.contains(baconFrame)
    frameCtrl.contains(mngtFrame)
    radioCtrl.contains(frameCtrl)

    return radioCtrl.get_packet()
    
def generate_auth_response(vbssid, dst_addr, channel):
    '''
    Generates auth response for the given (vbssid,dst_addr) tuple.
    '''
    dst = mac_to_array(dst_addr)
    bssid = mac_to_array(vbssid)

    # Radiotap Header
    radioCtrl = dot11.RadioTap(aBuffer = RADIOTAP_STR)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        channel_flags = 0x000a
        rate = 0x02
    else:
        channel_flags = 0x0140
        rate = 0x0c
    freq = CHANNEL_FREQS[channel]
    radioCtrl.set_rate(rate)
    radioCtrl.set_channel(freq,channel_flags)

    
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
    radioCtrl.contains(frameCtrl)

    return radioCtrl.get_packet()

def generate_assoc_response(vbssid, dst_addr, params, channel, capa, ht_capa, assoc_id, reassoc=False):
    '''
    Generates assoc response for the given vbssid,dst_addr tuple.
    if reassoc is true, it sends a reassociation response frame.
    '''
    #log.debug("%s, %s" % (ssid, bssid))
    dst = mac_to_array(dst_addr)
    bssid = mac_to_array(vbssid)

    # Radiotap Header
    radioCtrl = dot11.RadioTap(aBuffer = RADIOTAP_STR)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        channel_flags = 0x000a
        rate = 0x02
    else:
        channel_flags = 0x0140
        rate = 0x0c
    freq = CHANNEL_FREQS[channel]
    radioCtrl.set_rate(rate)
    radioCtrl.set_channel(freq,channel_flags)


    # Frame Control
    frameCtrl = dot11.Dot11(FCS_at_end = False)
    frameCtrl.set_version(0)
    if reassoc==True:
        frameCtrl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_REASSOCIATION_RESPONSE)
    else:
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
    if reassoc==True:
        assocFrame = dot11.Dot11ManagementReassociationResponse()
    else:
        assocFrame = dot11.Dot11ManagementAssociationResponse()
    assocFrame.set_capabilities(capa)
    assocFrame.set_status_code(0)
    # bits 14-15 need to be set on the response, not the kernel.
    assocFrame.set_association_id(assoc_id | 0xc000) 
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        assocFrame.set_supported_rates(WLAN_2_GHZ_SUPP_RATES)
        assocFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x30\x48\x60\x6c")
    else:
        assocFrame.set_supported_rates(WLAN_5_GHZ_SUPP_RATES)
    
    # HT Capabilities
    ht_capa_info_str = struct.pack('H',ht_capa)
    ht_capa_rest_str = HT_CAPA_STR_BASE
    ht_capa_str = ht_capa_info_str + ht_capa_rest_str
    assocFrame._set_element(45,ht_capa_str)
    # HT info
    ht_info_ch_str = chr(channel)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        ht_info_oper_str = chr(0)
    else:
        ht_info_oper_str = chr(5)
    ht_info_str_rest = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ht_info_str = ht_info_ch_str + ht_info_oper_str + ht_info_str_rest
    assocFrame._set_element(61, ht_info_str)
    # Extended Capabilities
    ext_capab_str = "\x00\x00\x00\x00\x00\x00\x00\x40"
    assocFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXTENDED_CAPABILITIES, ext_capab_str)

    # Add WMM/QoS
    wmm_str = "\x02\x01\x01\x04\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"
    assocFrame.add_vendor_specific("\x00\x50\xf2",wmm_str)


    mngtFrame.contains(assocFrame)
    frameCtrl.contains(mngtFrame)
    radioCtrl.contains(frameCtrl)

    return radioCtrl.get_packet()

def generate_beacon(vbssid, ssid, channel, capa, ht_capa):
    '''
    Generates beacon for the given (vbssid, ssid) tuple.
    '''
    bssid = mac_to_array(vbssid)

    # Radiotap Header
    radioCtrl = dot11.RadioTap(aBuffer = RADIOTAP_STR)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        channel_flags = 0x000a
        rate = 0x02
    else:
        channel_flags = 0x0140
        rate = 0x0c
    freq = CHANNEL_FREQS[channel]
    radioCtrl.set_rate(rate)
    radioCtrl.set_channel(freq,channel_flags)


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
    baconFrame.set_capabilities(capa)
    baconFrame.set_beacon_interval(BEACON_INTERVAL)
    baconFrame.set_ds_parameter_set(channel)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        baconFrame.set_supported_rates(WLAN_2_GHZ_SUPP_RATES)
        baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x30\x48\x60\x6c")
    else:
        baconFrame.set_supported_rates(WLAN_5_GHZ_SUPP_RATES)
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.ERP_INFO,"\x02")
    # Country code
    baconFrame._set_element(7,COUNTRY_STR)
    # HT Capabilities
    ht_capa_info_str = struct.pack('H',ht_capa)
    ht_capa_rest_str = HT_CAPA_STR_BASE
    ht_capa_str = ht_capa_info_str + ht_capa_rest_str
    baconFrame._set_element(45,ht_capa_str)
    # HT info
    ht_info_ch_str = chr(channel)
    if channel < WLAN_2_GHZ_CHANNEL_MAX:
        ht_info_oper_str = chr(0)
    else:
        ht_info_oper_str = chr(5)
    ht_info_str_rest = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ht_info_str = ht_info_ch_str + ht_info_oper_str + ht_info_str_rest
    baconFrame._set_element(61, ht_info_str)
    # Extended Capabilities
    ext_capab_str = "\x00\x00\x00\x00\x00\x00\x00\x40"
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXTENDED_CAPABILITIES, ext_capab_str)
 
    mngtFrame.contains(baconFrame)
    frameCtrl.contains(mngtFrame)
    radioCtrl.contains(frameCtrl)

    return radioCtrl.get_packet()

def generate_action_response(vbssid, dst_addr):
    '''
    Generates action response for BlockAck for the given (vbssid,dst_addr) tuple.
    '''
    dst = mac_to_array(dst_addr)
    bssid = mac_to_array(vbssid)
    
    # Frame Control
    frameCtrl = dot11.Dot11(FCS_at_end = False)
    frameCtrl.set_version(0)
    frameCtrl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_ACTION)
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
    
    frameCtrl.contains(mngtFrame)
    
    block_ack_str = "\x03\x01\x08\x00\x00\x02\x10\x00\x00"

    resp_str = frameCtrl.get_packet()
    #log.debug("length of pkt : %d" % len(resp_str))
    
    packet_str = RADIOTAP_STR + resp_str + block_ack_str
    return packet_str

class WifiStaParams(object):
    def __init__(self, buf=None, reassoc=False):
        mgmt_frame = dot11.Dot11ManagementFrame(buf[2:])
        if reassoc:
            assoc_req = dot11.Dot11ManagementReassociationRequest(mgmt_frame.get_frame_body())
        else:
            assoc_req = dot11.Dot11ManagementAssociationRequest(mgmt_frame.get_frame_body())
        self.addr = mgmt_frame.get_source_address()
        self.supp_rates = assoc_req.get_supported_rates()
        self.listen_interval = assoc_req.get_listen_interval()
        self.capabilities = assoc_req.get_capabilities()
        self.vendor_specific = assoc_req.get_vendor_specific()
        self.ext_rates = assoc_req.get_ext_supported_rates()
        self.ht_capabilities = assoc_req.get_ht_capabilities()

    def __str__(self):
        return "src : %s | supp_rates : %s | ext_rates : %s |" \
            "list_interval : %d | capa : %s | ht-capabililites : %s" % (binascii.hexlify(self.addr),self.supp_rates,
                                                self.ext_rates, self.listen_interval, self.capabilities,
                                                self.ht_capabilities)
                                                                                                 
class WifiStaParamsSample(object):
    def __init__(self, addr=None, supp_rates=None, listen_interval=None,capabilities=None,
                 vendor_specific=None, ext_rates=None, ht_capabilities=None):
        self.addr = addr
        self.supp_rates = supp_rates
        self.listen_interval = listen_interval
        self.capabilities = capabilities
        self.ext_rates = None
        self.ht_capabilities = ht_capabilities


class UnknownTransitionError(Exception):
    pass

class FSM(object):
    def __init__(self, init_state):
        self.state = init_state
        self.inputs = []
        self.states = []
        self.transitions = {}

    def add_transition(self, state, input, action, next_state):
        self.transitions[(input,state)] = {'handler':action, 'next_state':next_state}

    def get_transition(self, input, state):
        try:
            transition = self.transitions[(input,state)]
        except KeyError:
            log.debug("Unknown Transition Requested : %s, %s" % (input, state))
            raise UnknownTransitionError
            transition = None
        return transition

    def processFSM(self, state, input, *args):
        transition = self.get_transition(input, state)
        if transition == None:
            return
        if transition['handler']:
            transition['handler'](*args)
        return transition['next_state']

class AssociationFSM(FSM):
    def __init__(self):
        self.states = ['SNIFF','IDLE','RESERVED','AUTH','ASSOC']
        self.inputs = ['ProbeReq','AuthReq','AssocReq','Timeout','DeauthReq','DisassocReq']
        FSM.__init__(self, 'SNIFF')
        self.add_transition('SNIFF','ProbeReq',self.sniff_to_reserve,'RESERVED')
        self.add_transition('SNIFF','AuthReq', None, 'SNIFF')
        self.add_transition('SNIFF','AssocReq',None, 'SNIFF')
        self.add_transition('RESERVED','ProbeReq',self.reinstallSendProbeResponse,'RESERVED')
        self.add_transition('RESERVED','AuthReq',self.sendAuthResponse,'AUTH')
        self.add_transition('RESERVED','AssocReq',self.reinstallSendAssocResponse,'ASSOC')
        self.add_transition('RESERVED','ReassocReq',self.reinstallSendReassocResponse,'ASSOC')
        self.add_transition('RESERVED','DisassocReq',None,'RESERVED')
        self.add_transition('RESERVED','DeauthReq',None,'RESERVED')
        self.add_transition('AUTH','ProbeReq',self.reinstallSendProbeResponse,'AUTH')
        self.add_transition('AUTH','AuthReq',self.reinstallSendAuthResponse,'AUTH')
        self.add_transition('AUTH','AssocReq',self.auth_to_assoc,'ASSOC')
        self.add_transition('AUTH','ReassocReq',self.reinstallSendReassocResponse,'ASSOC')
        self.add_transition('ASSOC','ProbeReq',self.reinstallSendProbeResponse,'ASSOC')
        self.add_transition('ASSOC','AuthReq',self.reinstallSendAuthResponse,'ASSOC')
        self.add_transition('ASSOC','AssocReq',self.reinstallSendAssocResponse,'ASSOC')
        self.add_transition('ASSOC','ReassocReq',self.reinstallSendReassocResponse,'ASSOC')        
        self.add_transition('ASSOC','DisassocReq',self.delete_station, 'NONE')
        self.add_transition('AUTH','DisassocReq',self.delete_station, 'NONE')
        self.add_transition('ASSOC','DeauthReq',self.delete_station, 'NONE')        
        self.add_transition('AUTH','DeauthReq',self.delete_station, 'NONE')        
        self.add_transition('ASSOC','HostTimeout',self.delete_station, 'NONE')

    def sniff_to_reserve(self, *args):
        pass

    def auth_to_assoc(self, *args):
        pass

    def sendProbeResponse(self, *args):
        pass

    def sendAuthResponse(self, *args):
        pass

    def sendAssocResponse(self, *args):
        pass

    def reinstallSendProbeResponse(self, *args):
        pass

    def reinstallSendAuthResponse(self, *args):
        pass

    def reinstallSendAssocResponse(self, *args):
        pass


class ProbeRequest(Event):
    '''Event raised by an AP when a probe request is received.
    @radioap : the RadioAP reporting the request
    @src_addr : host's address
    @snr: the snr of the packet
    '''
    def __init__(self, radioap, src_addr, snr, ssid):
        Event.__init__(self)
        self.radioap = radioap
        self.src_addr = src_addr
        self.snr = snr
        self.ssid = ssid
    
class AuthRequest(Event):
    '''Event raised by an AP when a probe request is received.
    @virtualap : the Virtual AP reporting the request
    @src_addr : host's address
    @bssid : the bssid for the authentication
    @snr: the snr of the packet
    '''
    def __init__(self, virtualap, src_addr, bssid, snr):
        Event.__init__(self)
        self.virtualap = virtualap
        self.src_addr = src_addr
        self.bssid = bssid
        self.snr = snr

class AssocRequest(Event):
    '''Event raised by an AP when a probe request is received.
    @virtualap : the VirtualAP reporting the request
    @src_addr : host's address
    @bssid : the bssid for the assocation
    @snr: the snr of the packet
    @params : the Wifi params
    '''
    def __init__(self, virtualap, src_addr, bssid, snr, params):
        Event.__init__(self)
        self.virtualap = virtualap
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
    def __init__(self, virtualap, src_addr, bssid, snr, params):
        Event.__init__(self)
        self.virtualap = virtualap
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
    def __init__(self, virtualap, src_addr, bssid, reason):
        Event.__init__(self)
        self.virtualap = virtualap
        self.src_addr = src_addr
        self.bssid = bssid
        self.reason = reason

    def __str__(self):
        return "dpid:%012x | src_addr:%012x | bssid:%012x" % (self.dpid, self.src_addr, self.bssid)

class DeauthRequest(Event):
    '''Event raised by an AP when a deauth request is received.
    @dpid : the AP reporting the request.
    @src_addr : host's address
    @bssid : the bssid from which the disassoc is reported.
    '''
    def __init__(self, virtualap, src_addr, bssid, reason):
        Event.__init__(self)
        self.virtualap = virtualap
        self.src_addr = src_addr
        self.bssid = bssid
        self.reason = reason

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

class AddVBeacon(Event):
    def __init__(self, dpid, intf, vbssid):
        Event.__init__(self)
        self.dpid = dpid
        self.intf = intf
        self.vbssid = vbssid

class DelVBeacon(Event):
    def __init__(self, dpid, intf, vbssid):
        Event.__init__(self)
        self.dpid = dpid
        self.intf = intf
        self.vbssid = vbssid

