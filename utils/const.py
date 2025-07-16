import os

module_dir        = 'modules'
Version           = '0.8.5'
banner            = -1
priv_key          = 'shencode_priv_key.pem'
pub_key           = 'shencode_pub_key.pem'

if os.name == 'nt':
  json_dir        = 'resources\\json\\'
  msfvenom_path   = "msfvenom.bat"
  nasm            = 'nasm.exe'
  resource_dir    = 'resources\\'
  tpl_path =      'tpl\\'
elif os.name == 'posix':
  json_dir        = 'resources/json/'
  msfvenom_path   = 'msfvenom'
  nasm            = 'nasm'
  resource_dir    = 'resources/'
  tpl_path        = 'tpl/'
