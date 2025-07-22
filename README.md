# ShenCode

> **A versatile tool for working with shellcodes.**

![](shencode085.png)

## Features

ShenCode is a framework for developing, analyzing and testing shellcodes. It supports the following operating modes:

- Argument mode
	- `shencode core output -i file.raw -s inspect`
- [[getting-started#Interactive|Interactive mode]]
	- `shencode$ load output`
	- `shencode::core::output$`
- [[task|Task mode]]
	- Automate modules in different steps with `json`

### Version 0.8.5

#### General usage

Check out [ShenCode Docs](https://heckhausen.it/shencode/wiki/) and [the starter tutorial](https://heckhausen.it/shencode/wiki/getting-started) for more information.

#### Modules

| Category    | Description                      | Modules                                                                                                                                                                                                                                                                                                                                                                                                                |
| ----------- | -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `core`      | Shencode core functions          | [download](https://www.heckhausen.it/shencode/core/download) - [extract](https://www.heckhausen.it/shencode/core/extract)- [minidump](https://www.heckhausen.it/shencode/core/minidump) - [output](https://www.heckhausen.it/shencode/core/output) - [subproc](https://www.heckhausen.it/shencode/core/subproc) - [task](https://www.heckhausen.it/shencode/core/task)                                                 |
| `encoder`   | Shellcode encoder                | [alphanum](https://www.heckhausen.it/shencode/encoder/alphanum) - [bytebert](https://www.heckhausen.it/shencode/encoder/bytebert) - [byteswap](https://www.heckhausen.it/shencode/encoder/byteswap)[^byteswap] - [multicoder](https://www.heckhausen.it/shencode/encoder/multicoder) - [xor](https://www.heckhausen.it/shencode/encoder/xor) - [xorpoly](https://www.heckhausen.it/shencode/encoder/xorpoly)[^xorpoly] |
| `inject`    | Process injection modules        | [dll](https://www.heckhausen.it/shencode/inject/dll) - [injection](https://www.heckhausen.it/shencode/inject/injection) - [linject](https://www.heckhausen.it/shencode/inject/linject) - [ntinjection](https://www.heckhausen.it/shencode/inject/ntinjection) - [psoverwrite](https://www.heckhausen.it/shencode/inject/psoverwrite)[^psoverwrite]                                                                     |
| `obfuscate` | Shellcode obfuscation techniques | [feed](https://www.heckhausen.it/shencode/obfuscate/feed) - [qrcode](https://www.heckhausen.it/shencode/obfuscate/qrcode) - [rolhash](https://www.heckhausen.it/shencode/obfuscate/rolhash) - [uuid](https://www.heckhausen.it/shencode/obfuscate/uuid)                                                                                                                                                                |
| `payload`   | Modules to generate payloads     | [msfvenom](https://www.heckhausen.it/shencode/payload/msfvenom) - [winexec](https://www.heckhausen.it/shencode/payload/winexec)                                                                                                                                                                                                                                                                                        |
| `stager`    | Stage loaders                    | [meterpreter](https://www.heckhausen.it/shencode/stager/meterpreter) - [sliver](https://www.heckhausen.it/shencode/stager/sliver)                                                                                                                                                                                                                                                                                      |

## How to use

##### Install

```shell
git clone https://github.com/psycore8/shencode
cd shencode
python -m venv .venv
<! ACTIVATE-VENV-SEE-BELOW !>
pip install .
shencode -h
```

To activate the virtual environment use the following command:

- Windows - `.venv\bin\activate`
- Linux - `source .venv/bin/activate`

## Release Notes

- `general` - fixed some fstring errors 
- `core/minidump` - dump a process from memory to disk
- `inject/linject` - Linux based injection method
- `inject/psoverwrite` - Fixed NoCFG setting
- `obfuscate/feed` - open file optimizations
- `stager/sliver` - save the stage to disk 
- `stager/sliver` - testing linux support
- `utils/interactive` - print config in json format
- `utils/style` - moved style settings from helper to style

## References

- [Byte-Swapping](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping)
- [In-Memory Decoder](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder)
- [Function Name Hashing](https://www.bordergate.co.uk/function-name-hashing/)
- [Win32API with python3 injection](https://systemweakness.com/win32api-with-python3-part-iii-injection-6dd3c1b99c90)
- [Violent python: XOR Encryption](https://samsclass.info/124/proj14/VPxor.htm)
- [How to easily encrypt file in python](https://www.stackzero.net/how-to-easily-encrypt-file-in-python/)


- [^byteswap]: [Byteswapping Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping)
- [^xorpoly]: [Polymorphic XOR decoder Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder)
- [^psoverwrite]: [hasherezade](https://github.com/hasherezade/process_overwriting)