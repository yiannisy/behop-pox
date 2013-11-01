import impacket.dot11 as dot11
from impacket.ImpactDecoder import RadioTapDecoder
import dpkt
import binascii
import struct
import random
from pox.core import core
from behop_config import *

RADIOTAP_STR = '\x00\x00\x18\x00\x6e\x48\x00\x00\x00\x0c\x3c\x14\x40\x01\xa8\x81\x02\x00\x00\x00\x00\x00\x00\x00'
HT_CAPA_STR_BASE = "\x1b\xff\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

HOMENETS_OUI = "020000" # needs to be better defined.
BEACON_INTERVAL = 1000
DEFAULT_CHANNEL = 11

log = core.getLogger("WifiMaster")
log_fsm = core.getLogger("WifiFSM")

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
    baconFrame.set_supported_rates([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x30\x48\x60\x6c")
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.ERP_INFO,"\x02")
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

def generate_assoc_response(vbssid, dst_addr, params, channel, capa, ht_capa, assoc_id):
    '''
    Generates assoc response for the given vbssid,dst_addr tuple.
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
    assocFrame.set_capabilities(capa)
    assocFrame.set_status_code(0)
    # bits 14-15 need to be set on the response, not the kernel.
    assocFrame.set_association_id(assoc_id | 0xc000) 
    assocFrame.set_supported_rates([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x18, 0x30, 0x48])
    assocFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x12\x24\x60\x6c")
    
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
    baconFrame.set_supported_rates([0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24])
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES, "\x30\x48\x60\x6c")
    baconFrame._set_element(dot11.DOT11_MANAGEMENT_ELEMENTS.ERP_INFO,"\x02")
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
    def __init__(self, buf=None):
        mgmt_frame = dot11.Dot11ManagementFrame(buf[2:])
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
        self.add_transition('AUTH','ProbeReq',self.reinstallSendProbeResponse,'AUTH')
        self.add_transition('AUTH','AuthReq',self.reinstallSendAuthResponse,'AUTH')
        self.add_transition('AUTH','AssocReq',self.auth_to_assoc,'ASSOC')
        self.add_transition('ASSOC','ProbeReq',self.reinstallSendProbeResponse,'ASSOC')
        self.add_transition('ASSOC','AuthReq',self.reinstallSendAuthResponse,'ASSOC')
        self.add_transition('ASSOC','AssocReq',self.reinstallSendAssocResponse,'ASSOC')
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

