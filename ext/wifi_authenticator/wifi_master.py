"""
A WiFi Authenticator.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpid_to_str
from pox.lib.util import str_to_bool
import time

import dpkt, binascii

log = core.getLogger()

WLAN_TYPE_MGMT = 0
WLAN_SUBTYPE_PROBE_REQUEST = 4
WLAN_SUBTYPE_PROBE_RESPONSE = 5

PROBE_RESPONSE_STR = "\x00\x00\x1a\x00\x2f\x48\x00\x00\x93\x44\x1f\x90\x4e\x4e\x00\xd2\x10\x02\x6c\x09\xa0\x00\xdb\x01\x00\x00\x50\x00\x3a\x01\xc8\x3a\x35\xcf\xcc\x37\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\xc0\x37\xb0\xdb\x28\x05\x00\x00\x00\x00\x64\x00\x01\x04\x00\x06\x70\x69\x2d\x61\x70\x31\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x03\x01\x01\x2a\x01\x06\x32\x04\x30\x48\x60\x6c\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00\x28\xf3\xe0\x3a"

AUTH_REPLY_STR = "\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xd9\x01\x00\x00\xb0\x00\x3a\x01\xc8\x3a\x35\xcf\xcc\x37\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x70\x3a\x00\x00\x02\x00\x00\x00"

ASSOC_REPLY_STR="\x00\x00\x12\x00\x2e\x48\x00\x00\x00\x02\x6c\x09\xa0\x00\xd7\x01\x00\x00\x10\x00\x3a\x01\xc8\x3a\x35\xcf\xcc\x37\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x01\x80\x3a\x01\x04\x00\x00\x01\xc0\x01\x08\x82\x84\x8b\x96\x0c\x12\x18\x24\x32\x04\x30\x48\x60\x6c\xdd\x18\x00\x50\xf2\x02\x01\x01\x00\x00\x03\xa4\x00\x00\x27\xa4\x00\x00\x42\x43\x5e\x00\x62\x32\x2f\x00"



class WifiAuthenticateSwitch(object):
    def __init__(self, connection, transparent):
        self.connection = connection
        self.transparent = transparent
        
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        if event.port != 3:
            #print "not monitor port - ignore (port:%d)" % event.port
            return
        packet = event.parsed
        rdtap = dpkt.radiotap.Radiotap(packet.raw)
        rd_len = rdtap.length >> 8
        if rdtap.version != 0 or rd_len != 18:
            print "unrecognized rdtap header - ignore... (%d, %d)" % (rdtap.version, rd_len)
            return

        ie = dpkt.ieee80211.IEEE80211(packet.raw[rd_len:])

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_BEACON):
            return

        print binascii.hexlify(packet.raw[rd_len:rd_len+8])

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_PROBE_REQ):
            print "sending probe response!!!"
            self.send_packet_out(PROBE_RESPONSE_STR)

        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_AUTH):
            print "sending auth reply!!!"
            self.send_packet_out(AUTH_REPLY_STR)
            
        if (ie.type == dpkt.ieee80211.MGMT_TYPE and ie.subtype == dpkt.ieee80211.M_ASSOC_REQ):
            print "sending assoc reply!!!"
            self.send_packet_out(ASSOC_REPLY_STR)

        if (ie.type == 0 and ie.subtype != 8):
            print "Received %x from %s" % (ie.subtype, binascii.hexlify(ie.mgmt.src))
       

    def send_packet_out(self, msg_raw):
        msg = of.ofp_packet_out(in_port=of.OFPP_NONE)
        msg.actions.append(of.ofp_action_output(port = 3))
        msg.data = msg_raw
        self.connection.send(msg)




class WifiAuthenticator(object):
    def __init__(self, transparent):
        core.openflow.addListeners(self)
        self.transparent = transparent

    def _handle_ConnectionUp(self, event):
        log.debug("Connection %s" % (event.connection))
        WifiAuthenticateSwitch(event.connection, self.transparent)

def launch( transparent=False):
    core.registerNew(WifiAuthenticator, str_to_bool(transparent))
            
