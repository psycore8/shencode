# ShenCode

A multi purpose tool for shellcode operations


![](shencode-051.png)
## Features

### Version 0.5.1

- general
	- `extract` - [extract](https://github.com/psycore8/shencode/wiki/extract) from/to offset
	- `formatout` - [display raw shellcodes](https://github.com/psycore8/shencode/wiki/formatout) in `C++, C#` and more
	- `inject` - [inject shellcode](https://github.com/psycore8/shencode/wiki/inject) into process (Windows only)
	- `msfvenom` - [create payloads](https://github.com/psycore8/shencode/wiki/msfvenom)  with msfvenom
- encoder
	- `aesenc` - [Encrypt](https://github.com/psycore8/shencode/wiki/aesenc) payload with AES
	- `xorenc` - [Encode payload](https://github.com/psycore8/shencode/wiki/xorenc) with custom XOR key
	- `xorpoly` - [polymorphic x64](https://github.com/psycore8/shencode/wiki/xorpoly) in-memory decoder (for details, visit this [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder))
- obfuscator
	- `QR-Code` hide OpCodes as [QR-Code image](https://github.com/psycore8/shencode/wiki/qrcode)
	- `ROR13` to `ROL` [conversion with custom key](https://github.com/psycore8/shencode/wiki/ror2rol) (Windows only)
	- `UUID` [obfuscation](https://github.com/psycore8/shencode/wiki/uuid) - Please, check out my [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_shellcode_als_uuids_tarnen_-_teil_1) about this encoder

## Release Notes

#### Improvements

- `formatout` - fixed unterminated %-sign in `-h` output
- `aesenc` - module to en-/decrypt shellcodes with AES
- `sha1` - checksum module for files (internal use only)

## How to use

Check out the [ShenCode Wiki](https://github.com/psycore8/shencode/wiki/) for more information.

## References

- [Function Name Hashing](https://www.bordergate.co.uk/function-name-hashing/)
- [Win32API with python3 injection](https://systemweakness.com/win32api-with-python3-part-iii-injection-6dd3c1b99c90)
- [Violent python: XOR Encryption](https://samsclass.info/124/proj14/VPxor.htm)
- [How to easily encrypt file in python](https://www.stackzero.net/how-to-easily-encrypt-file-in-python/)
