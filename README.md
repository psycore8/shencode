# ShenCode

**A versatile tool for working with shellcodes.**

![](shencode-060.png)

## Features

<<<<<<< Updated upstream
### Version 0.6.0
=======
### Version 0.6.2
>>>>>>> Stashed changes

- general
	- `extract` - [extract](https://github.com/psycore8/shencode/wiki/extract) from/to offset
	- `formatout` - [display raw shellcodes](https://github.com/psycore8/shencode/wiki/formatout) in `C++, C#` and more
	- `inject` - [inject shellcode](https://github.com/psycore8/shencode/wiki/inject) into process (Windows only)
	- `msfvenom` - [create payloads](https://github.com/psycore8/shencode/wiki/msfvenom)  with msfvenom
- encoder
	- `aesenc` - [Encrypt](https://github.com/psycore8/shencode/wiki/aesenc) payload with AES
	- `byteswap` - New XOR Encryption, [Swapping Bytes](https://github.com/psycore8/shencode/wiki/byteswap) ([Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping))
	- `xorenc` - [Encode payload](https://github.com/psycore8/shencode/wiki/xorenc) with custom XOR key
	- `xorpoly` - [polymorphic x64](https://github.com/psycore8/shencode/wiki/xorpoly) in-memory decoder (for details, visit this [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder))
- obfuscator
	- `QR-Code` hide OpCodes as [QR-Code image](https://github.com/psycore8/shencode/wiki/qrcode)
	- `ROR13` to `ROL` [conversion with custom key](https://github.com/psycore8/shencode/wiki/ror2rol) (Windows only)
	- `UUID` [obfuscation](https://github.com/psycore8/shencode/wiki/uuid) - Please, check out my [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_shellcode_als_uuids_tarnen_-_teil_1) about this encoder

## How to use

Check out the [ShenCode Docs](https://heckhausen.it/shencode/wiki/) for more information.

## Release Notes

<<<<<<< Updated upstream
#### Improvements
=======
- `inject` - Suspend and Resume Technique
- `inject` - VirtuakProtectEx Technique
- `feed` - A new obfuscation module
- `core` - added some different logos for startup
>>>>>>> Stashed changes

- `byteswap` - New XOR Encryption, Swapping Bytes
- `core` - Tested on Linux and Windows
- `core` - Output optimizations
- `core` - Better class implementations
- `core` - Fixed Linux import error
- `formatout` - Missing comma at EOL of C# output
- `formatout` - `--no-break` disable line break in output
- `extract` - Replaced `--first-byte` with `--start-offset` argument
- `extract` - Replaced `--last-byte` with `--end-offset` argument
- `extract` - Short arguments are `-so / -eo` 
- `qrcode` - Fixed non functional implementation
- `xorpoly` - Code optimizations
- 
## References

- [Byte-Swapping](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping)
- [In-Memory Decoder](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder)
- [Function Name Hashing](https://www.bordergate.co.uk/function-name-hashing/)
- [Win32API with python3 injection](https://systemweakness.com/win32api-with-python3-part-iii-injection-6dd3c1b99c90)
- [Violent python: XOR Encryption](https://samsclass.info/124/proj14/VPxor.htm)
- [How to easily encrypt file in python](https://www.stackzero.net/how-to-easily-encrypt-file-in-python/)
