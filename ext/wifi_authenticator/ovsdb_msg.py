"""
Adds/Removes Stations from Access Points.
"""

from pox.core import core
from pox.messenger import *

log = core.getLogger()


class OvsDBBot(ChannelBot):

    def _handle_MessageReceived(self, event, msg):
        if msg['method'] == 'echo':
            self.send_echo_reply(event.con, msg)

    def send_echo_reply(self, con, msg):
        con.send({"result":msg['params'],"error":None, 'id':msg['id']})

class OvsDBManager(object):
    def __init__(self):
        core.listen_to_dependencies(self)
        log.debug("OvsDBManager Started")

    def _all_dependencies_met(self):
        log.debug("Dependencies Met!!")
        core.MessengerNexus.default_bot.add_bot(OvsDBBot)
        OvsDBBot(core.MessengerNexus.get_channel(""))

def launch():
    OvsDBManager()
