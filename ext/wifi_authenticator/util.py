import sqlite3
from behop_config import *
from wifi_params import *

def get_lan_from_wan_1(wan_addr):
    lan = (wan_addr - 1) | 0x020000000000
    return lan

def get_lan_from_wan_2(wan_addr):
    lan = (wan_addr - 1)
    return lan


def load_sta_whitelist_from_db(db=BEHOP_DB_FILE):
    
    conn = sqlite3.connect(db)
    c = conn.cursor()

    c.execute("select addr,dpid from mac_user_dpid where opt_out == \"0\"")    
    conn.commit()
    w_stas = {int(x[0],16):int(x[1],16) for x in c.fetchall()}
    conn.close()
    return w_stas

def load_sta_whitelist_from_file(fname=WHITELIST_FNAME):
    w_stas = []
    f = open(fname,'r')
    for line in f.readlines():
        if line.startswith('#'):
            continue
        w_stas.append(int(line.rstrip(), 16))
    f.close()
    log.info("Updated List of Whitelisted STAs:")
    for sta in w_stas:
        log.info("%012x" % sta)
    return w_stas

