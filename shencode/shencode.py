########################################################################
#
# ShenCode
# Autor:      psycore8
# Repo:       https://github.com/psycore8/shencode
# Web:        https://www.heckhausen.it
#
########################################################################

from utils.args import parse_arguments
import utils.args
#from utils.helper import nstate as nstate
from utils.const import *
from utils.style import *
import utils.header
import utils.interactive
#import utils.helper
import importlib
import json

print(f"{HEADER}")
print(f'{utils.header.get_header(banner)}')
print(f'Version {Version} by psycore8 -{ENDC} {TextLink("https://github.com/psycore8/shencode")}\n')
arguments = parse_arguments()

config = None
if arguments.config != None:
  with open(arguments.config, 'r') as f:
      config = json.load(f)
  
def main(command_line=None):
  if config != None:
     argd = config
  elif arguments.interactive:
     utils.interactive.interactive_mode()
  else:
    argd = arguments.__dict__
  mod = importlib.import_module(f'modules.{argd["command"]}')
  del argd['config']
  del argd['module']
  del argd['command']
  del argd['interactive']
  class_init = mod.module(**argd)
  class_init.process()

if __name__ == "__main__":
   main()

