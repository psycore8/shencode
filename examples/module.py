import utils.arg
from utils.helper import nstate as nstate

class example:
  Author =      'Name'
  Description = 'some useful information about this module'
  Version =     '1.0.0'

  # python shencode.py examplemod -i input.txt -l yes
  def init():
    spName = 'examplemod'
    spArgList = [
        # shortflag, flag, choices=, action=, default=, type=, required=, help=)
          ['-i', '--input', None, None, None, str, True, 'Input file for example module'],
          ['-t', '--truestate', None, 'store_true', False, bool, False, 'store_true switch'],
          ['-l', '--list', ['yes', 'no'], None, None, list, True, 'A list of choices for this argument']
        ]
    utils.arg.CreateSubParserEx(spName, example.Description, spArgList)

    def process():
      print('python is nice')