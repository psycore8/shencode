# ShenCode

**A versatile tool for working with shellcodes.**

![](shencode-070.png)

## Features

### Version 0.7.0

- **core**
	- `extract` - [extract](https://www.heckhausen.it/shencode/wiki/core/extract) from/to offset
	- `formatout` - [display raw shellcodes](https://www.heckhausen.it/shencode/wiki/core/formatout) in `C++, C#` and more
	- `injection` - [inject shellcode](https://www.heckhausen.it/shencode/wiki/core/injection) into process (Windows only)
	- `msfvenom` - [create payloads](https://www.heckhausen.it/shencode/wiki/core/msfvenom)  with msfvenom
- **encoder**
	- `aes` - [Encrypt](https://www.heckhausen.it/shencode/wiki/encoder/aes) payload with AES
	- `bytebert` - advanced polymorphic encoder
	- `byteswap` - New XOR Encryption, [Swapping Bytes](https://www.heckhausen.it/shencode/wiki/encoder/byteswap) ([Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping))
	- `xor` - [Encode payload](https://www.heckhausen.it/shencode/wiki/encoder/xor) with custom XOR key
	- `xorpoly` - [polymorphic x64](https://www.heckhausen.it/shencode/wiki/encoder/xorpoly) in-memory decoder (for details, visit this [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder))
- **obfuscate**
	- `Feed` - Splits Bytes in a [feed.xml file](https://www.heckhausen.it/shencode/wiki/obfuscate/feed) as article IDs
	- `QR-Code` hide OpCodes as [QR-Code image](https://www.heckhausen.it/shencode/wiki/obfuscate/qrcode)
	- `ROR13` to `ROL` [conversion with custom key](https://www.heckhausen.it/shencode/wiki/obfuscate/rolhash) (Windows only)
	- `UUID` [obfuscation](https://www.heckhausen.it/shencode/wiki/obfuscate/uuid) - Please, check out my [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_shellcode_als_uuids_tarnen_-_teil_1) about this encoder
-  **stager**
	- `meterpreter` - Initiate a `meterpreter/reverse_tcp` [stage](https://www.heckhausen.it/shencode/wiki/stager/meterpreter)
	- `sliver` - Initiate a `https` [sliver stage](https://www.heckhausen.it/shencode/wiki/stager/sliver)

## How to use

##### Install

```shell
git clone https://github.com/psycore8/shencode
cd shencode
pip install .
shencode -h
```

#### General usage

Check out the [ShenCode Docs](https://heckhausen.it/shencode/wiki/) for more information.

## Release Notes

- `general` - setup routine, which handles the different packages and modules for Windows and Linux
- `general` - new module parser
- `general` - new start-up banners
- `core/inject` - Suspend and Resume Technique
- `core/inject` - VirtualProtectEx Technique
- `encoder/bytebert` - advanced polymorphic encoder
- `stager/meterpreter` - a reverse TCP Meterpreter stager
- `stager/sliver` - a HTTPS Sliver stager

## References

- [Byte-Swapping](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping)
- [In-Memory Decoder](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder)
- [Function Name Hashing](https://www.bordergate.co.uk/function-name-hashing/)
- [Win32API with python3 injection](https://systemweakness.com/win32api-with-python3-part-iii-injection-6dd3c1b99c90)
- [Violent python: XOR Encryption](https://samsclass.info/124/proj14/VPxor.htm)
- [How to easily encrypt file in python](https://www.stackzero.net/how-to-easily-encrypt-file-in-python/)
