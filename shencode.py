import os

from utils.args import parse_arguments
from utils.helper import nstate as nstate
from utils.helper import FileCheck
import utils.header
import utils.helper
import importlib

Version = '0.8.1'
# if you want a static banner, specify it here
banner = -1

print(f"{nstate.HEADER}")
print(f'{utils.header.get_header(banner)}')
print(f'Version {Version} by psycore8 -{nstate.ENDC} {nstate.TextLink('https://www.nosociety.de')}\n')
arguments = parse_arguments()

# make sure your metasploit binary folder is in your PATH variable
if os.name == 'nt':
  msfvenom_path = "msfvenom.bat"
  tpl_path = 'tpl\\'
elif os.name == 'posix':
  msfvenom_path = 'msfvenom'
  tpl_path = 'tpl/'
  
def main(command_line=None):
  argd = arguments.__dict__
  #mod = argd['command']
  mod = importlib.import_module(f'modules.{argd['command']}')
  del argd['module']
  del argd['command']
  class_init = mod.module(**argd)
  class_init.process()

if __name__ == "__main__":
   main()

