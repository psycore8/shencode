#import os

from utils.args import parse_arguments
from utils.helper import nstate as nstate
#from utils.helper import FileCheck
from utils.const import *
import utils.header
import utils.helper
import importlib
import json

print(f"{nstate.HEADER}")
print(f'{utils.header.get_header(banner)}')
print(f'Version {Version} by psycore8 -{nstate.ENDC} {nstate.TextLink('https://www.nosociety.de')}\n')
arguments = parse_arguments()

config = None
if arguments.config != None:
  with open(arguments.config, 'r') as f:
      config = json.load(f)
  
def main(command_line=None):
  if config != None:
     argd = config
  else:
    argd = arguments.__dict__
  mod = importlib.import_module(f'modules.{argd['command']}')
  del argd['config']
  del argd['module']
  del argd['command']
  class_init = mod.module(**argd)
  class_init.process()

if __name__ == "__main__":
   main()

