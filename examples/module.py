########################################################
### ShenCode Module
###
### Name: Example Module
### Docs: https://heckhausen.it/shencode/README
### 
########################################################

from utils.style import *

# defines a category
CATEGORY    = 'example'
DESCRIPTION = 'An example module for ShenCode'

# Console style definitions
cs = ConsoleStyles()

# the arglist defines argument defaults and descriptions
arglist = {
   'base':      { 'value': None, 'desc': 'The base' },
   'exponent':  { 'value': None, 'desc': 'The exponent' },
   'verbose':   { 'value': False, 'desc': 'Verbose output' }
}

# defines the parser arguments
def register_arguments(parser):
    parser.add_argument('-b', '--base', type=int, help=arglist['base']['desc'])
    parser.add_argument('-e', '--exponent', type=int, help=arglist['exponent']['desc'])
    parser.add_argument('-v', '--verbose', action='store_true', help=arglist['verbose']['desc'])

class module:
  # general information
  Author =      'Name'
  Version =     '0.9.0'
  DisplayName = 'CALC-POWER'
  # relay is used in tasked mode
  relay_input = False
  relay_output = False
  shell_path = '::example::power'

  # class init
  def __init__(self, base=0, exponent=0, power=0, verbose=False):
    self.base           = base
    self.exponent       = exponent
    self.power          = power
    self.verbose        = verbose

  def CalculatePower(self):
     # executes functions in process()
     self.power = pow(self.base,self.exponent)

  def process(self):
    # prints module header
    # [CALC-POWER]-[0.9.0]
    cs.module_header(self.DisplayName, self.Version)

    # executes function
    self.CalculatePower()

    # check for tasked mode
    if not self.relay_output:
      # prints the result
      if self.verbose:
        # [+] The base of 8 raised to the exponent of 4 results in the power value 4096
        cs.console_print.ok('The base of 8 raised to the exponent of 4 results in the power value 4096')
      else:
        # [+] The result equals 4096
        cs.console_print.ok('The result equals 4096')
    else:
       # returns the values to task module for further processing
       value_list = [self.base, self.exponent, self.power]
       return value_list