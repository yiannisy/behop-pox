# AP variables
WAN_PORT  = 1 # ethernet port
MON_PORT  = 2 # monitor port where we expect mgmt packets from.
WLAN_PORT = 3 # wireless port
SERVING_SSID = 'malakas'
BASE_HW_ADDRESS = 0x020000000000

# BH parameters
BH_UPLINK_PORT = 1
BH_AP_PRIO = 1
BH_STA_PRIO = 1

ASSOC_TIMEOUT = 5
VBSSID_RANGE_MIN = 20
VBSSID_RANGE_MAX = 40

GOOD_SNR_THRESHOLD = 35
SNR_SWITCH_THRESHOLD = 10
DEFAULT_HOST_TIMEOUT = 5 * 60

# Blacklist, Whitelist
USE_BLACKLIST = 1
USE_WHITELIST = 1
BLACKLIST_FNAME = 'ext/wifi_authenticator/ap_blacklist.txt'
WHITELIST_FNAME = 'ext/wifi_authenticator/sta_whitelist.txt'
BW_LIST_UPDATE_INTERVAL= 5*60

# topology
BACKHAUL_SWITCH = 0x030012e27831d8
BEHOP_UPLINK = 1
BEHOP_TOPO = { 0xf81a6752fd7e:2, 0xf81a67531193:3, 0x6466b393fa74:4, 0x6466b378fe78:5 }
