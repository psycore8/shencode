########################################################################
#
# ShenCode
# Autor:      psycore8
# Repo:       https://github.com/psycore8/shencode
# Web:        https://www.heckhausen.it
#
########################################################################

from utils.args import parse_arguments
from utils.const import *
from utils.style import *
import utils.header
import utils.interactive
import importlib
import json

debug = False

cs = ConsoleStyles()

#cs.print(f"{HEADER}")
cs.print(f'[bright_magenta]{utils.header.get_header(banner)}[/]')
cs.print(f'[bright_magenta]Version [bold]{Version}[/bold] by psycore8 -[/] [bright_blue u]https://github.com/psycore8/shencode[/]\n')
arguments = parse_arguments()

config = None
if arguments.config != None:
  with open(arguments.config, 'r') as f:
      config = json.load(f)
      if debug: cs.log(config)
  
def main(command_line=None):
  if config != None:
     argd = config
     if debug: cs.log(argd)
  elif arguments.interactive:
     if debug: cs.log('Interactive mode')
     utils.interactive.interactive_mode()
  else:
    argd = arguments.__dict__
    if debug: cs.log(argd)
  mod = importlib.import_module(f'modules.{argd["command"]}')
  del argd['config']
  del argd['module']
  del argd['command']
  del argd['interactive']
  class_init = mod.module(**argd)
  if debug: cs.log(class_init)
  class_init.process()

if __name__ == "__main__":
   main()

