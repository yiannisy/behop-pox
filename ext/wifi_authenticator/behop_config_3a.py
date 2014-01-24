VBSSID_RANGE_MIN = 1
VBSSID_RANGE_MAX = 40

SERVING_SSID = 'TY is cool!'

# topology
#BACKHAUL_SWITCH = 0x020012e298a5ce
IS_GATES_NETWORK = True
BACKHAUL_SWITCH = 0x030012e27831d8
BACKHAUL_MGMT_UPLINK = 1
BACKHAUL_DATA_UPLINK = 1
BEHOP_TOPO = { 
    0x204E7F73FAD1:4,
    }
BEHOP_CHANNELS = { 
    0x100d7f64c8ec:36,
    0x4c60ded0f3b9:36,
    0x100d7f64c12d:36,
    0x100d7f64c931:36
    }
DEFAULT_BEHOP_CHANNEL=36
BEHOP_DB_FILE="/home/yiannis/of/pi-dev/utils/nodeDB.sqlite"
LOAD_WHITELIST_FROM_DB=False
WHITELIST_FNAME="/home/yiannis/behop-pox-netgear/ext/wifi_authenticator/sta_whitelist.txt"

#VBSSID_RANGE_MIN = 35
#VBSSID_RANGE_MAX = 40

#SERVING_SSID = 'FlashFest'

# topology
#BACKHAUL_SWITCH = 0x040012e27831d8
#BACKHAUL_UPLINK = 1
#BEHOP_TOPO = { 0xf81a6752fd7e:2, 0xf81a67531193:3, 0x6466b393fa74:4, 0x6466b378fe78:5 }
#BEHOP_CHANNELS = { 0xc43dc7b01d0b:36 }
#BEHOP_DB_FILE="/home/yiannis/of/pi-dev/utils/nodeDB.sqlite"
#LOAD_WHITELIST_FROM_DB=True
