import impacket.dot11 as dot11
import binascii
import struct
from pox.core import core

HOMENETS_OUI = "020000" # needs to be better defined.
log = core.getLogger("WifiMaster")

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
