from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
import time
from pox.web.webcore import *
import json

import select

import random
import hashlib
import base64
import json

from pox.lib.recoco import Timer


log = core.getLogger()

class ImagAppRequest(Event):
  '''Event to raise upon a request from web interfaces'''

  def __init__(self, ip, ip_dst, service, state):
    Event.__init__(self)
    self.ip = ip
    self.ip_dst = ip_dst
    self.service = service
    self.state = state

class imagapp_web(EventMixin):
  _eventMixin_events = set([ImagAppRequest])

  def __init__(self):
    EventMixin.__init__(self)
    self.listenTo(core)

class HttpMsgHandler(SplitRequestHandler):
  protocol_version = 'HTTP/1.1'

  def do_GET(self):
    if self.path.find("manage") != -1:
      self.do_manage()
      return
    if self.path.find("stats") != -1:
      self.do_stats()
      return
    if self.path.find("index") != -1:
      self.do_control()
      return
    if self.path.find("topo") != -1:
      self.do_topo()
      return
    else:
      return

  def do_control(self):
    ip = None
    ip_dst = None
    args = self.path.split('?')[1]
    arg_vars = args.split('&')
    if arg_vars[0].split('=')[0] == 'ip':
      ip  = arg_vars[0].split('=')[1]
    elif arg_vars[0].split('=')[0] == 'ip_dst':
      ip_dst = arg_vars[0].split('=')[1]
    if arg_vars[1].split('=')[0] == 'service':
      service = arg_vars[1].split('=')[1]
    if arg_vars[2].split('=')[0] == 'state':
      state = arg_vars[2].split('=')[1]
    if (ip or ip_dst) and state:
      core.imagapp_web.raiseEvent(ImagAppRequest(ip, ip_dst, service, state))
    self.send_info()
    return

  def do_manage(self):
    self.send_console()
    return

  def do_stats(self):
    stats = {}
    stats['default_stats'] = "%08.2f Mbps" % core.imagapp.default_rate
    stats['voip_stats'] = "%08.2f Mbps" % core.imagapp.voip_tx_bytes
    stats['video_stats'] = "%08.2f Mbps" % core.imagapp.video_rate
    r = json.dumps(stats)
    self.send_response(200)
    self.send_header("Content-type", "text/json")
    self.end_headers()
    self.wfile.write(r)
    

  def do_topo(self):
    topo = {"nodes" : [ {"name" : "cloud", "group":0 }, { "name" : "switch", "group":0 }, { "name" : "ap", "group":0}, {"name" : "client", "group":0}, {"name": "phone", "group":0}, {"name": "videof1", "group": 1}, {"name": "videof2", "group": 1}, {"name": "voipf1", "group":2},  {"name": "voipf2", "group":2}, {"name": "voipf3", "group":2}  ] , "links" : [ { "source" : 0, "target" : 1, "name":"line0"}, { "source" : 1, "target" : 2, "name":"line1" }, { "source" : 2, "target" : 3, "name":"line2" }, {"source": 2, "target":4, "name":"line3"}, {"source": 5, "target": 6, "name":"video"}, {"source": 7, "target": 8, "name":"voip1"}  , {"source": 8, "target": 9, "name":"voip2"}], "services":[]}
    if core.imagapp.is_video_on == True:
      topo["services"].append("video")
    if core.imagapp.is_voip_on == True:
      topo["services"].append("voip")
    r = json.dumps(topo)
    self.send_response(200)
    self.send_header("Content-type","text/json")
    self.end_headers()
    self.wfile.write(r)

  def do_POST(self):
    log.debug("Received a POST!")
    l = self.headers.get("Content-Length", "")
    if l != '':
      print "found length %d" % int(l)
      print self.rfile.read(int(l))
    else:
      print "length not set"
      print self.rfile.read()
  
  def send_info(self):
    r = "<html><head><title>POX-ImagApp</title></head\n"
    r += "<body>\n<h1>Hi TY!</h1>\n"
    r += "</body></html>\n"
    self.send_response(200)
    self.send_header("Content-type", "text/html")
    self.send_header("Content-Length", str(len(r)))
    self.end_headers()
    self.wfile.write(r)

  def send_console(self):
    root_filename = "./ext/www_root/index.html"
    f = open(root_filename)
    r = f.read()
    self.send_response(200)
    self.send_header("Content-Length", str(len(r)))
    self.end_headers()
    self.wfile.write(r)

    
def launch (transparent=False, username='', password=''):
  """
  Starts the imagapp application.
  """
  if not core.hasComponent("WebServer"):
    log.error("WebServer is required but unavailable")
    return
  else:
    log.debug("webserver found!")

  # source = core.registerNew(HTTPMessengerSource)

  # # Set up config info
  # config = {"source":source}
  # if len(username) and len(password):
  #   config['auth'] = lambda u, p: (u == username) and (p == password)

  core.registerNew(imagapp_web)

  core.WebServer.set_handler("/_myboost/", HttpMsgHandler)
