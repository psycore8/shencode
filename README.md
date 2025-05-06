# ShenCode

> **A versatile tool for working with shellcodes.**

![](shencode-082.png)

## Features

### Version 0.8.3

| Category    | Module        | Description                                    | Docs                                                                      | Refs                                                                                                      |
| ----------- | ------------- | ---------------------------------------------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| `core`      | `download`    | Download remote files                          | [download](https://www.heckhausen.it/shencode/wiki/core/download)         |                                                                                                           |
| `core`      | `extract`     | Extract a range of bytes from a file           | [extract](https://www.heckhausen.it/shencode/wiki/core/extract)           |                                                                                                           |
| `core`      | `output`      | Inspect and display files in different formats | [output](https://www.heckhausen.it/shencode/wiki/core/output)             |                                                                                                           |
| `core`      | `subproc`     | Execute an external subprocess                 | [subproc](https://www.heckhausen.it/shencode/wiki/core/subproc)           |                                                                                                           |
| `core`      | `task`        | Execute tasks to automate ShenCode             | [task](https://www.heckhausen.it/shencode/wiki/core/task)                 |                                                                                                           |
| `encoder`   | `aes`         | Encrypt with AES                               | [aes](https://www.heckhausen.it/shencode/wiki/encoder/aes)                |                                                                                                           |
| `encoder`   | `alphanum`    | Alphanumeric encoder to avoid null bytes       | [alphanum](https://www.heckhausen.it/shencode/wiki/encoder/alphanum)      |                                                                                                           |
| `encoder`   | `bytebert`    | Advanced polymorphic encoder                   | [bytebert](https://www.heckhausen.it/shencode/wiki/encoder/bytebert)      |                                                                                                           |
| `encoder`   | `byteswap`    | New XOR Encryption, Swapping Bytes             | [byteswap](https://www.heckhausen.it/shencode/wiki/encoder/byteswap)      | [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping)                        |
| `encoder`   | `multicoder`  | Multi-Algorithm encoder                        | [multicoder](https://www.heckhausen.it/shencode/wiki/encoder/multicoder)  |                                                                                                           |
| `encoder`   | `xor`         | Encode payload with custom XOR key             | [xor](https://www.heckhausen.it/shencode/wiki/encoder/xor)                |                                                                                                           |
| `encoder`   | `xorpoly`     | Polymorphic x64 in-memory decoder              | [xorpoly](https://www.heckhausen.it/shencode/wiki/encoder/xorpoly)        | [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder)       |
| `inject`    | `dll`         | Inject dll into a process                      | [dll](https://www.heckhausen.it/shencode/wiki/inject/dll)                 |                                                                                                           |
| `inject`    | `injection`   | Inject shellcode into a process                | [injection](https://www.heckhausen.it/shencode/wiki/inject/injection)     |                                                                                                           |
| `inject`    | `ntinjection` | Inject with native windows API                 | [ntinjection](https://www.heckhausen.it/shencode/wiki/inject/ntinjection) |                                                                                                           |
| `inject`    | `psoverwrite` | Process overwriting injection                  | [psoverwrite](https://www.heckhausen.it/shencode/wiki/inject/psoverwrite) | [hasherezade](https://github.com/hasherezade/process_overwriting)                                         |
| `obfuscate` | `feed`        | Hide shellcode bytes in a feed.xml file        | [feed](https://www.heckhausen.it/shencode/wiki/obfuscate/feed)            |                                                                                                           |
| `obfuscate` | `qrcode`      | Generate QR-Code from a file                   | [qrcode](https://www.heckhausen.it/shencode/wiki/obfuscate/qrcode)        |                                                                                                           |
| `obfuscate` | `rolhash`     | ROR13 to custom ROL hashing                    | [rolhash](https://www.heckhausen.it/shencode/wiki/obfuscate/rolhash)      |                                                                                                           |
| `obfuscate` | `uuid`        | Generate UUIDs from shellcode                  | [uuid](https://www.heckhausen.it/shencode/wiki/obfuscate/uuid)            | [Blog Post](https://www.nosociety.de/en:it-security:blog:obfuscation_shellcode_als_uuids_tarnen_-_teil_1) |
| `payload`   | `msfvenom`    | Create payloads with msfvenom                  | [msfvenom](https://www.heckhausen.it/shencode/wiki/payload/msfvenom)      |                                                                                                           |
| `payload`   | `winexec`     | Create a shellcode with custom WinExec command | [winexec](https://www.heckhausen.it/shencode/wiki/payload/winexec)        |                                                                                                           |
| `stager`    | `meterpreter` | Download a meterpreter reverse tcp stage       | [meterpreter](https://www.heckhausen.it/shencode/wiki/stager/meterpreter) |                                                                                                           |
| `stager`    | `sliver`      | Download  a sliver stage                       | [sliver](https://www.heckhausen.it/shencode/wiki/stager/sliver)           |                                                                                                           |

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

#### General usage

Check out [ShenCode Docs](https://heckhausen.it/shencode/wiki/) and [the starter tutorial](https://heckhausen.it/shencode/wiki/getting-started) for more information.

## Release Notes

- `encoder/alphanum` - fixed wrong register in decoder stub

## References

- [Byte-Swapping](https://www.nosociety.de/en:it-security:blog:obfuscation_byteswapping)
- [In-Memory Decoder](https://www.nosociety.de/en:it-security:blog:obfuscation_polymorphic_in_memory_decoder)
- [Function Name Hashing](https://www.bordergate.co.uk/function-name-hashing/)
- [Win32API with python3 injection](https://systemweakness.com/win32api-with-python3-part-iii-injection-6dd3c1b99c90)
- [Violent python: XOR Encryption](https://samsclass.info/124/proj14/VPxor.htm)
- [How to easily encrypt file in python](https://www.stackzero.net/how-to-easily-encrypt-file-in-python/)
