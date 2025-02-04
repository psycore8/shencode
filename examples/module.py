from utils.helper import nstate as nstate

CATEGORY = 'core'

def register_arguments(parser):
    parser.add_argument('-i', '--input', help='text1')
    parser.add_argument('-o', '--output', help='text2')
    parser.add_argument('-x', '--xray', action='store_true', help='text3')
    parser.add_argument('-z', '--zulu', help='text4')

class example:
  Author =      'Name'
  Description = 'some useful information about this module'
  Version =     '1.0.0'

  def process():
    print('python is nice')