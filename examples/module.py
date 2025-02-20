from utils.helper import nstate as nstate

# defines a category
CATEGORY = 'example'

# defines the parser arguments
def register_arguments(parser):
    parser.add_argument('-b', '--base', type=int, help='the base')
    parser.add_argument('-e', '--exponent', type=int, help='the exponent')
    parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')

class example:
  # general information
  Author =      'Name'
  Description = 'some useful information about this module'
  Version =     '1.0.0'
  DisplayName = 'CALC-POWER'

  # class init
  def __init__(self, base=0, exponent=0, power=0, verbose=False):
    self.base           = base
    self.exponent       = exponent
    self.power          = power
    self.verbose        = verbose

  # defines the console output
  def msg(self, message_type, ErrorExit=False):
    messages = {
        'pre.head'       : f'{nstate.FormatModuleHeader(self.DisplayName, self.Version)}\n',
        'proc.calcs'     : f'{nstate.s_ok} The result equals {self.power}',
        'proc.calcv'     : f'{nstate.s_ok} The base of {self.base} raised to the exponent of {self.exponent} results in the power value {self.power}'
    }
    print(messages.get(message_type, f'{message_type} - this message type is unknown'))
    if ErrorExit:
        exit()

  def CalculatePower(self):
     # executes functions in process()
     self.power = pow(self.base,self.exponent)

  def process(self):
    # prints module header
    # [CALC-POWER]-[1.0.0]
    self.msg('pre.head')

    # executes function
    self.CalculatePower()

    # prints the result
    if self.verbose:
      # [+] The base of 8 raised to the exponent of 4 results in the power value 4096
      self.msg('proc.calcv')
    else:
      # [+] The result equals 4096
      self.msg('proc.calcs')