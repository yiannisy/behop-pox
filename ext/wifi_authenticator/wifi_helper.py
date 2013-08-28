import impacket.dot11 as dot11
import binascii
import struct

HOMENETS_OUI = "020000" # needs to be better defined.

class WifiStaParams(object):
    def __init__(self, buf=None):
        rdtap = dot11.RadioTap(aBuffer=buf)
        mgmt_frame = dot11.Dot11ManagementFrame(buf[20:])
        print binascii.hexlify(mgmt_frame.get_source_address())
        assoc_req = dot11.Dot11ManagementAssociationRequest(mgmt_frame.get_frame_body())
        print assoc_req.get_supported_rates(human_readable=True)
        self.addr = mgmt_frame.get_source_address()
        self.supp_rates = assoc_req.get_supported_rates()
        self.ext_rates = assoc_req._get_element(dot11.DOT11_MANAGEMENT_ELEMENTS.EXT_SUPPORTED_RATES)
        self.listen_interval = assoc_req.get_listen_interval()
        self.capabilities = assoc_req.get_capabilities()
        self.vendor_specific = assoc_req.get_vendor_specific()
        print self.vendor_specific
        if (self.ext_rates):
            _ext_rates=struct.unpack('%dB'%len(self.ext_rates),self.ext_rates)
            print tuple(map(lambda x: 0.5*x, _ext_rates))

    def __str__(self):
        return "src : %s" % binascii.hexlify(self.addr)


def is_homenets_bssid(bssid):
    return  bssid.startswith(HOMENETS_OUI)
