#from datetime import datetime
#import sys
import subprocess
import utils.assist as assist

class msfvenom:
  def CreateShellcode(msfvenom_path,payload,arg1,arg2):
    h = assist.helper
    file_name = str(h.GenerateFileName())
    subprocess.run([msfvenom_path, "-p", payload, arg1, arg2, "-e", "generic/none", "--format", "raw", "-o", file_name])
    return file_name
   