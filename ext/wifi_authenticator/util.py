import sqlite3
from behop_config import *
from wifi_params import *
import string

def get_lan_from_wan_1(wan_addr):
    lan = (wan_addr - 1) | 0x020000000000
    return lan

def get_lan_from_wan_2(wan_addr):
    lan = (wan_addr - 1)
    return lan


def load_sta_whitelist_from_db(db=BEHOP_DB_FILE):
    w_stas = {}
    try:
        conn = sqlite3.connect(db)
        c = conn.cursor()
        
        c.execute("select addr,dpid from mac_user_dpid where opt_out == \"0\"")    
        conn.commit()
        w_stas = {int(x[0],16):int(x[1],16) for x in c.fetchall()}
        conn.close()
    except:
        print "Cannot load sta whitelist database"
    return w_stas

def load_sta_whitelist_from_file(fname=WHITELIST_FNAME):
    w_stas = {}
    f = open(fname,'r')
    for line in f.readlines():
        if line.startswith('#'):
            continue
        vals = string.split(line.rstrip(),',')
        w_stas[int(vals[0],16)] = int(vals[1],16)
    f.close()
    return w_stas

