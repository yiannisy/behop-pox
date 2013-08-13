# Copyright 2011 James McCauley
#
# This file is part of POX.
#
# POX is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# POX is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with POX.  If not, see <http://www.gnu.org/licenses/>.

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.util import str_to_bool
from pox.lib.addresses import EthAddr
import time
from pox.web.webcore import *

import select

import random
import hashlib
import base64
import json

from pox.lib.recoco import Timer

DROID_MAC="78d6f074909c"
MAC_MAC = "001ff35576dd"
PI_DPID=0xb827eb6ba1f0

log = core.getLogger()

# We don't want to flood immediately when a switch connects.
FLOOD_DELAY = 5

class DumpSwitch(EventMixin):
  def __init__(self, connection, transparent, dpid):
    self.connection = connection
    self.transparent = transparent
    self.dpid = dpid

    self.listenTo(connection)
    self.listenTo(core.imagapp_web)

    log.debug("Setting default flows to AP")
    self._set_simple_flow(1,2)
    self._set_simple_flow(2,1)
    self._set_simple_flow(2,1,priority=2,ip='192.168.12.24')
    self._set_simple_flow(2,1,priority=2,ip='192.168.12.23')

    # if (dpidToStr(dpid) == '54-e6-fc-98-62-42'):
    #   log.debug("This is the AP")
    #   # self._set_simple_flow(1,2)
    #   self._set_simple_flow(2,1)
    #   self._set_simple_flow(4,1)
    #   self._set_simple_l2_flow(port_in=1,dl_dst=EthAddr(DROID_MAC), port_out=4)
    #   self._set_simple_l2_flow(port_in=1,dl_dst=EthAddr(MAC_MAC), port_out=2)
    #   self._set_simple_l2_flood(port_in=1)
    # else:
    #   log.debug("This is the Pronto!")
    #   self._set_simple_flow(2,1,1)
    #   self._set_simple_flow(26,25)
    #   self._set_simple_flow(25,2)
    #   self._set_boosted_flow(2,1, '50.201.10.56',2)

  def _handle_ImagAppRequest(self, event):
    # log.debug("%x : Boosting Request : IP:%s, State:%s" % (self.dpid, event.ip, event.state))
    if event.state == '1' and event.service == 'lastmile':
      print "setting up for last-mile service"
      self._set_boosted_flow(2,1,ip='192.168.12.23',queue_id=1,reverse=True)
      self._set_boosted_flow(2,1,ip='192.168.12.24',queue_id=2,reverse=True)
    elif event.state == '0' and event.service == 'lastmile':
      print "tearing down last-mile service"
      self._del_boosted_flow(2,1,ip='192.168.12.23',queue_id=0, priority=8,reverse=True)
      self._del_boosted_flow(2,1,ip='192.168.12.24',queue_id=0, priority=8,reverse=True)
      # install again - can't remove only the high priority ones...?
      self._set_simple_flow(2,1,priority=2,ip='192.168.12.24')
      self._set_simple_flow(2,1,priority=2,ip='192.168.12.23')

    elif event.state == '1' and event.service == 'wireless':
      self._set_boosted_flow(2,1,ip='192.168.12.23',queue_id=6,reverse=True)
      self._set_boosted_flow(2,1,ip='192.168.12.24',queue_id=1,reverse=True)
      print "setting up wireless service"
    elif event.state == '0' and event.service == 'wireless':
      print "tearing down wireless service"
      self._del_boosted_flow(2,1,ip='192.168.12.23',queue_id=0,priority=8,reverse=True)
      self._del_boosted_flow(2,1,ip='192.168.12.24',queue_id=0,priority=8,reverse=True)
      self._set_simple_flow(2,1,priority=2,ip='192.168.12.23')
      self._set_simple_flow(2,1,priority=2,ip='192.168.12.24')
    else:
      print "unknown service"

    return

         
      #   else:
      #     queue_id = 1
      #   if event.ip != None:
      #     log.debug("Boosting Flow for %s!!!" % event.ip)
      #     self._set_boosted_flow(2,1, event.ip, queue_id)
      #   elif event.ip_dst != None:
      #     log.debug("Boosting Flow for %s!!!" % event.ip_dst)
      #     self._set_boosted_flow(2,1, event.ip_dst, queue_id, priority=3,reverse=True)
      # elif event.state == '0':
      #   if event.ip != None:
      #     log.debug("Deleting Boost for Flow %s!!!" % event.ip)
      #     self._del_boosted_flow(2,1, event.ip, 2)
      #   elif event.ip_dst != None:
      #     log.debug("Deleting Boost for Flow %s!!!" % event.ip_dst)
      #     self._del_boosted_flow(2,1, event.ip_dst, 2, reverse=True)
        


#    if (dpidToStr(self.dpid) != '54-e6-fc-98-62-42'):
#      if event.state == 1:
#        self._set_boosted_flow(2,1,2,1
        
          
  def _handle_PacketIn(self, event):
    packet = event.parse()
    if self.dpid == None:
      log.debug("no dpid in here")
    else:
      pass      

  def _set_simple_flow(self,port_in,port_out, priority=1,ip=None, queue_id=None):
    msg = of.ofp_flow_mod()
    msg.idle_timeout=0
    msg.priority = priority
    msg.match.in_port = port_in
    if ip:
      msg.match.dl_type = 0x0800
      msg.match.nw_dst = ip
    if queue_id == None:
      msg.actions.append(of.ofp_action_output(port = port_out))
    else:
      msg.actions.append(of.ofp_action_enqueue(port = port_out, queue_id = queue_id))
    self.connection.send(msg)

  def _set_simple_l2_flow(self,port_in,port_out, dl_dst=None,queue_id=None):
    msg = of.ofp_flow_mod()
    msg.idle_timeout=0
    msg.priority = 1
    msg.match.in_port = port_in
    if dl_dst != None:
      msg.match.dl_dst = dl_dst
    if queue_id == None:
      msg.actions.append(of.ofp_action_output(port = port_out))
    else:
      msg.actions.append(of.ofp_action_enqueue(port = port_out, queue_id = queue_id))
    self.connection.send(msg)

  def _set_simple_l2_flood(self, port_in):
    msg = of.ofp_flow_mod()
    msg.idle_timeout=0
    msg.priority = 1
    msg.match.in_port = port_in
    msg.match.dl_type = 0x0806
    msg.actions.append(of.ofp_action_output(port=2))
    msg.actions.append(of.ofp_action_output(port=4))
    self.connection.send(msg)

  def _set_boosted_flow(self, port_in, port_out, ip, queue_id, priority=8,reverse=False):
    msg = of.ofp_flow_mod()
    #msg.command = of.OFPFC_MODIFY
    #msg.flags = of.OFPFF_CHECK_OVERLAP
    msg.idle_timeout = 0
    msg.priority = priority
    msg.match.in_port = port_in
    msg.match.dl_type = 0x0800
    if reverse == False:
      msg.match.nw_src = ip
    else:
      msg.match.nw_dst = ip
    msg.actions.append(of.ofp_action_enqueue(port = port_out, queue_id = queue_id))
    self.connection.send(msg)

  def _del_boosted_flow(self, port_in, port_out, ip, queue_id, priority=None,reverse=False):
    msg = of.ofp_flow_mod(command=of.OFPFC_DELETE)
    msg.match.in_port = port_in
    msg.match.dl_type = 0x0800
    if priority:
      msg.match.priority = priority
    if reverse == False:
      msg.match.nw_src = ip
    else:
      msg.match.nw_dst = ip
    self.connection.send(msg)
      
                              


class imagapp (EventMixin):
  """
  Waits for OpenFlow switches to connect and makes them learning switches.
  """
  def __init__ (self, transparent):
    self.listenTo(core.openflow)
    self.listenTo(core.imagapp_web)

    self.transparent = transparent
    self._timer = None
    self.previous_default_tx_bytes = 0.0
    self.previous_video_tx_bytes = 0.0
    self.previous_voip_tx_bytes = 0.0

    self.default_tx_bytes = 0.0
    self.video_tx_bytes = 0.0
    self.voip_tx_bytes = 0.0
    
    self.video_rate = 0.0
    self.default_rate = 0.0

    self.default_count_offset = 0.0
    self.video_count_offset = 0.0
    self.voip_count_offset = 0.0
    self.default_count_previous = 0.0
    self.video_count_previous = 0.0
    self.voip_count_previous = 0.0
    self.is_video_on = False
    self.is_voip_on = False

    self._setTimer()


  def _handle_ConnectionUp (self, event):
    log.debug("Connection %s" % (event.connection,))
    DumpSwitch(event.connection, self.transparent, event.dpid)

  def _poll_stats(self):
    log.debug("polling for stats")
    flow_msg = of.ofp_flow_stats_request()
    #queue_msg = of.ofp_queue_stats_request(port_no=1, queue_id=of.OFPQ_ALL)
    stats_msg = of.ofp_stats_request(body=flow_msg, type=of.OFPST_FLOW)
    core.openflow.sendToDPID(PI_DPID, stats_msg.pack())

  def _setTimer(self):
    if self._timer: self._timer.cancel()
    self._timer = None
    self._timer = Timer(1, self._poll_stats, recurring=True)

  def _handle_FlowStatsReceived(self, event):
    log.debug("received stats")
    self.video_tx_bytes = 0
    self.default_tx_bytes = 0

    for stat in event.stats:
      if stat.match.nw_dst == "192.168.12.23":
        self.video_tx_bytes += stat.byte_count
      elif stat.match.nw_dst == "192.168.12.24":
        self.default_tx_bytes += stat.byte_count
      else:
        pass

    print "%f,%f" % (self.video_tx_bytes,self.default_tx_bytes)
    print "%f,%f" % (self.previous_video_tx_bytes, self.previous_default_tx_bytes)
    print "%f,%f" % (self.video_rate, self.default_rate)
    if self.video_tx_bytes > self.previous_video_tx_bytes:
      self.video_rate = (self.video_tx_bytes - self.previous_video_tx_bytes)*8/1e6
    else:
      self.video_rate = 0
    self.previous_video_tx_bytes = self.video_tx_bytes
        

    if self.default_tx_bytes > self.previous_default_tx_bytes:
      self.default_rate = (self.default_tx_bytes - self.previous_default_tx_bytes)*8/1e6
    else:
      self.default_rate = 0.0
    self.previous_default_tx_bytes = self.default_tx_bytes
    
  def _handle_ImagAppRequest(self, event):
    if event.state == '1' and event.service == 'voip':
      self.is_voip_on = True
    if event.state == '0' and event.service == 'voip':
      self.is_voip_on = False
    if event.state == '1' and event.service == 'video':
      self.is_video_on = True
    if event.state == '0' and event.service == 'video':
      self.is_video_on = False

def launch (transparent=False, username='', password=''):
  """
  Starts the imagapp application.
  """
  imag_app = core.registerNew(imagapp, str_to_bool(transparent))
