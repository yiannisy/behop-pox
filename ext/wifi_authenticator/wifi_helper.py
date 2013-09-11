import impacket.dot11 as dot11
import binascii
import struct
from pox.core import core

HOMENETS_OUI = "020000" # needs to be better defined.
log = core.getLogger("WifiMaster")

def mac_to_array(mac):
    s_mac = mac
    if (not isinstance(mac, str)):
        s_mac = "%012x" % mac
    a_mac = [int(x,16) for x in [s_mac[0:2], s_mac[2:4], s_mac[4:6],
                                 s_mac[6:8], s_mac[8:10], s_mac[10:]]]
    return a_mac

def generate_probe_response(vbssid, ssid, dst_addr):
    '''
    Generates probe response for the given (vbssid, ssid, dst_addr) tuple.
    '''
    rdtap =  dpkt.radiotap.Radiotap(RADIOTAP_STR)
        
    dst = mac_to_array(dst_addr)
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
    packet_str = RADIOTAP_STR + resp_str
    return packet_str
    
def generate_auth_response(vbssid, dst_addr):
    '''
    Generates auth response for the given (vbssid,dst_addr) tuple.
    '''
    rdtap =  dpkt.radiotap.Radiotap(RADIOTAP_STR)
        
    dst = mac_to_array(dst_addr)
    bssid = mac_to_array(vbssid)
    
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
    return packet_str

def generate_assoc_response(vbssid, dst_addr):
    '''
    Generates assoc response for the given vbssid,dst_addr tuple.
    '''
    rdtap =  dpkt.radiotap.Radiotap(RADIOTAP_STR)
    
    #log.debug("%s, %s" % (ssid, bssid))
    dst = mac_to_array(dst_addr)
    bssid = mac_to_array(vbssid)

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
    packet_str = RADIOTAP_STR + resp_str
    return packet_str

def generate_beacon(vbssid, ssid):
    '''
    Generates beacon for the given (vbssid, ssid) tuple.
    '''
    bssid = mac_to_array(vbssid)
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
    packet_str = RADIOTAP_STR + resp_str
    return packet_str

class WifiStaParams(object):
    def __init__(self, buf=None):
        rdtap = dot11.RadioTap(aBuffer=buf)
        mgmt_frame = dot11.Dot11ManagementFrame(buf[20:])
        log.debug(binascii.hexlify(mgmt_frame.get_source_address()))
        assoc_req = dot11.Dot11ManagementAssociationRequest(mgmt_frame.get_frame_body())
        log.debug(assoc_req.get_supported_rates(human_readable=True))
        self.addr = mgmt_frame.get_source_address()
        self.supp_rates = assoc_req.get_supported_rates()
        self.ext_rates = assoc_req._get_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES)
        self.listen_interval = assoc_req.get_listen_interval()
        self.capabilities = assoc_req.get_capabilities()
        self.vendor_specific = assoc_req.get_vendor_specific()
        log.debug(self.vendor_specific)
        if (self.ext_rates):
            _ext_rates=struct.unpack('%dB'%len(self.ext_rates),self.ext_rates)
            log.debug(tuple(map(lambda x: 0.5*x, _ext_rates)))

    def __str__(self):
        return "src : %s" % binascii.hexlify(self.addr)

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
        #log.debug("%s --%s--> %s" % (state,input, transition['next_state']))
        return transition['next_state']

class AssociationFSM(FSM):
    def __init__(self):
        self.states = ['SNIFF','IDLE','RESERVED','AUTH','ASSOC']
        self.inputs = ['ProbeReq','AuthReq','AssocReq','Timeout','DeauthReq','DisassocReq']
        FSM.__init__(self, 'SNIFF')
        self.add_transition('SNIFF','ProbeReq',self.sniff_to_reserve,'RESERVED')
        self.add_transition('SNIFF','AuthReq', None, 'SNIFF')
        self.add_transition('SNIFF','AssocReq',None, 'SNIFF')
        self.add_transition('RESERVED','ProbeReq',self.sendProbeResponse,'RESERVED')
        self.add_transition('RESERVED','AuthReq',self.sendAuthResponse,'AUTH')
        self.add_transition('RESERVED','AssocReq',None,'RESERVED')
        self.add_transition('AUTH','ProbeReq',self.sendProbeResponse,'AUTH')
        self.add_transition('AUTH','AuthReq',self.sendAuthResponse,'AUTH')
        self.add_transition('AUTH','AssocReq',self.auth_to_assoc,'ASSOC')
        self.add_transition('ASSOC','ProbeReq',self.sendProbeResponse,'ASSOC')
        self.add_transition('ASSOC','AuthReq',self.sendAuthResponse,'ASSOC')
        self.add_transition('ASSOC','AssocReq',self.sendAssocResponse,'ASSOC')

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
