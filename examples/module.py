import utils.arg
from utils.helper import nstate as nstate

class example:
  Author =      'Name'
  Description = 'some useful information about this module'
  Version =     '1.0.0'

  def init():
    spName = 'examplemod'
    spArgList = [
          ['-i', '--input', '', '', 'Input file for example module'],
          ['-t', '--truestate', '', 'store_true', 'store_true switch'],
          ['-l', '--list', 'a,b,c,d', '', 'A list of choices for this argument']
        ]
    utils.arg.CreateSubParser(spName, example.Description, spArgList)

    def process():
      print('python is nice')