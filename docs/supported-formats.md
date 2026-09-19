# Supported Binary and Container Formats

OpenCryptoDetect analyzes executables and firmware packages across several common container formats.

## Supported Formats

| Format | Magic Bytes | Description | Handling |
| :--- | :--- | :--- | :--- |
| **ELF** | `\x7fELF` | Executable and Linkable Format (Linux, RTOS, embedded) | Full parsing of code/data sections, symbol tables, and relocations. |
| **Mach-O** | `\xfe\xed\xfa\xce`, `\xcf\xfa\xed\xfe` | Apple Mach-O binaries | Parsing of CPU architecture, bitness, and segment disassembly. |
| **PE / COFF**| `MZ` (`0x4D5A`) | Microsoft Portable Executable | Code and data segment extraction. |
| **RAW_BIN** | None (Arbitrary) | Flat binary dumps, flash ROM images, bootloaders | Disassembled using prologue heuristics or user-specified `--arch` flag. |
| **INTEL_HEX**| `:...` | Intel HEX record format | Converted to linear byte segments before static disassembly. |
| **Archives** | `PK\x03\x04`, `070701`, `\x1f\x8b` | ZIP, TAR, CPIO, GZIP archives | Safely unpacked into sandboxed temp directory; nested executables analyzed. |

## Raw Binary Analysis
When inspecting raw firmware dumps or flash images without container headers:
```bash
ocd analyze router_flash.bin --arch arm
```
Specifying `--arch` instructs the disassembler to use the correct instruction set decoder (ARM, AArch64, x86, x86-64, MIPS, or RISC-V).
