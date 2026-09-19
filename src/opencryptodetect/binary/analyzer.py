"""Binary analyzer implementing function discovery, basic block partitioning, and CFG construction."""

from abc import ABC, abstractmethod
from pathlib import Path

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from opencryptodetect.architecture.architectures import ARCH_REGISTRY
from opencryptodetect.architecture.metadata import TargetArch
from opencryptodetect.binary.basic_blocks import BasicBlock
from opencryptodetect.binary.cfg import ControlFlowGraph
from opencryptodetect.binary.disassembler import DisassemblerEngine
from opencryptodetect.binary.functions import FunctionContext, Instruction
from opencryptodetect.binary.strings import extract_strings
from opencryptodetect.core.context import AnalysisContext
from opencryptodetect.core.exceptions import BinaryAnalysisError


class BinaryAnalyzer(ABC):
    """Abstract base class for binary reverse-engineering analyzers."""

    @abstractmethod
    def analyze(self, ctx: AnalysisContext) -> list[FunctionContext]:
        """Analyze binary and return discovered FunctionContext objects."""


class ElfCapstoneAnalyzer(BinaryAnalyzer):
    """ELF analyzer using pyelftools for section/symbol parsing and Capstone for disassembly."""

    def __init__(self, arch: TargetArch, bitness: int = 64, endianness: str = "little"):
        self.arch = arch
        self.bitness = bitness
        self.endianness = endianness
        self.disassembler = DisassemblerEngine(arch, bitness, endianness)

    def analyze(self, ctx: AnalysisContext) -> list[FunctionContext]:
        """Perform comprehensive binary analysis on ELF or raw binary."""
        file_path = ctx.file_path

        if ctx.file_format == "ELF":
            return self._analyze_elf(file_path, ctx)
        else:
            return self._analyze_raw(file_path, ctx)

    def _analyze_elf(self, file_path: Path, ctx: AnalysisContext) -> list[FunctionContext]:
        """Analyze ELF binary using pyelftools."""
        functions: list[FunctionContext] = []
        try:
            with file_path.open("rb") as f:
                elffile = ELFFile(f)
                ctx.is_stripped = True

                # Extract code and data sections
                code_sections: list[tuple[str, int, bytes]] = []
                data_sections: dict[int, tuple[int, bytes]] = {}  # vaddr -> (size, data)

                for section in elffile.iter_sections():
                    sec_name = section.name
                    sec_addr = section["sh_addr"]
                    sec_data = section.data()
                    flags = section["sh_flags"]

                    # Executable sections (SHF_EXECINSTR = 0x4)
                    if (flags & 0x4) or sec_name in (".text", ".init", ".fini"):
                        code_sections.append((sec_name, sec_addr, sec_data))
                        ctx.code_sections.append({
                            "name": sec_name,
                            "addr": sec_addr,
                            "size": len(sec_data),
                        })

                    # Data sections (.rodata, .data, etc.)
                    if sec_name in (".rodata", ".data", ".rdata", ".sdata") or (flags & 0x2):
                        data_sections[sec_addr] = (len(sec_data), sec_data)
                        ctx.data_sections[sec_name] = sec_data
                        # Extract strings from data sections
                        extracted = extract_strings(sec_data)
                        ctx.extracted_strings.extend([s for _, s in extracted])

                # Extract symbols
                symbols: dict[int, tuple[str, int]] = {}  # addr -> (name, size)
                symtab_section = None
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        symtab_section = section
                        ctx.is_stripped = False
                        for sym in section.iter_symbols():
                            st_type = sym["st_info"]["type"]
                            st_value = sym["st_value"]
                            st_size = sym["st_size"]
                            st_name = sym.name
                            if st_type in ("STT_FUNC", 2) and st_value > 0:
                                symbols[st_value] = (st_name or f"sub_{st_value:x}", st_size)

                # Parse Relocations
                relocs_by_offset: dict[int, bytes] = {}
                for section in elffile.iter_sections():
                    if section.name.startswith((".rel.", ".rela.")):
                        try:
                            for r in section.iter_relocations():
                                r_offset = r["r_offset"]
                                sym_idx = r["r_info_sym"]
                                if symtab_section:
                                    sym = symtab_section.get_symbol(sym_idx)
                                    target_sec_idx = sym["st_shndx"]
                                    if isinstance(target_sec_idx, int) and target_sec_idx < elffile.num_sections():
                                        target_sec = elffile.get_section(target_sec_idx)
                                        if target_sec and target_sec.name in ctx.data_sections:
                                            target_data = ctx.data_sections[target_sec.name]
                                            sym_val = sym["st_value"]
                                            addend = r.get("r_addend", 0)
                                            data_slice = target_data[sym_val + addend : sym_val + addend + 1024]
                                            if data_slice:
                                                relocs_by_offset[r_offset] = data_slice
                                                ctx.relocations.append({
                                                    "offset": r_offset,
                                                    "symbol": sym.name,
                                                    "section": target_sec.name,
                                                })
                        except Exception:
                            pass

                # If stripped or no functions found, use prologue scanning
                if not symbols:
                    symbols = self._scan_prologues(code_sections)

                # If still empty but we have code sections, disassemble code section as single/multiple functions
                if not symbols and code_sections:
                    for s_name, s_addr, s_data in code_sections:
                        symbols[s_addr] = (f"func_{s_addr:x}", len(s_data))

                # Analyze each discovered function
                for func_addr, (func_name, func_size) in sorted(symbols.items()):
                    func_ctx = self._disassemble_function(
                        func_addr=func_addr,
                        func_name=func_name,
                        func_size=func_size,
                        code_sections=code_sections,
                        data_sections=data_sections,
                        reloc_data=relocs_by_offset,
                    )
                    if func_ctx and func_ctx.instructions:
                        functions.append(func_ctx)

        except Exception as e:
            raise BinaryAnalysisError(f"Failed to analyze ELF binary: {e}")

        return functions

    def _analyze_raw(self, file_path: Path, ctx: AnalysisContext) -> list[FunctionContext]:
        """Analyze raw firmware binary using prologue scanning and linear sweep."""
        functions: list[FunctionContext] = []
        try:
            with file_path.open("rb") as f:
                raw_bytes = f.read()

            base_addr = 0x0
            code_sections = [(".raw_code", base_addr, raw_bytes)]
            data_sections = {base_addr: (len(raw_bytes), raw_bytes)}

            extracted = extract_strings(raw_bytes)
            ctx.extracted_strings.extend([s for _, s in extracted])

            symbols = self._scan_prologues(code_sections)
            if not symbols:
                symbols[base_addr] = ("raw_entry", len(raw_bytes))

            for func_addr, (func_name, func_size) in sorted(symbols.items()):
                func_ctx = self._disassemble_function(
                    func_addr=func_addr,
                    func_name=func_name,
                    func_size=func_size,
                    code_sections=code_sections,
                    data_sections=data_sections,
                )
                if func_ctx and func_ctx.instructions:
                    functions.append(func_ctx)
        except Exception as e:
            raise BinaryAnalysisError(f"Failed to analyze raw binary: {e}")

        return functions

    def _scan_prologues(
        self,
        code_sections: list[tuple[str, int, bytes]],
    ) -> dict[int, tuple[str, int]]:
        """Scan code bytes for architecture function prologues."""
        discovered: dict[int, tuple[str, int]] = {}
        meta = ARCH_REGISTRY.get(self.arch)
        if not meta:
            return discovered

        for s_name, s_addr, s_data in code_sections:
            for pat in meta.prologue_patterns:
                idx = 0
                while True:
                    idx = s_data.find(pat, idx)
                    if idx == -1:
                        break
                    addr = s_addr + idx
                    if addr not in discovered:
                        discovered[addr] = (f"sub_{addr:x}", 0)
                    idx += 4
        return discovered

    def _disassemble_function(
        self,
        func_addr: int,
        func_name: str,
        func_size: int,
        code_sections: list[tuple[str, int, bytes]],
        data_sections: dict[int, tuple[int, bytes]],
        reloc_data: dict[int, bytes] | None = None,
    ) -> FunctionContext | None:
        """Disassemble function body, construct CFG, and extract constants and references."""
        # Find the containing code section
        target_code: bytes | None = None
        for s_name, s_addr, s_data in code_sections:
            if s_addr <= func_addr < s_addr + len(s_data):
                offset = func_addr - s_addr
                max_len = func_size if func_size > 0 else min(4096, len(s_data) - offset)
                target_code = s_data[offset : offset + max_len]
                break

        if not target_code:
            return None

        instructions = self.disassembler.disassemble_bytes(target_code, func_addr)
        if not instructions:
            return None

        # Build basic blocks and CFG
        basic_blocks, cfg = self._build_cfg(func_addr, instructions)

        # Extract constants, referenced data, strings, and calls
        constants: set[int] = set()
        calls: list[int] = []
        referenced_data: dict[int, bytes] = {}
        opcode_stats: dict[str, int] = {}
        category_stats: dict[str, int] = {}

        # Add any relocations occurring within function instruction range
        if reloc_data:
            func_end = instructions[-1].address + instructions[-1].size
            for r_off, r_bytes in reloc_data.items():
                if func_addr <= r_off < func_end:
                    referenced_data[r_off] = r_bytes

        for insn in instructions:
            # Opcode stats
            opcode_stats[insn.mnemonic] = opcode_stats.get(insn.mnemonic, 0) + 1
            category_stats[insn.category] = category_stats.get(insn.category, 0) + 1

            # Immediates
            for imm in insn.immediate_values:
                constants.add(imm)
                # Check if immediate points to data section
                for d_addr, (d_size, d_bytes) in data_sections.items():
                    if d_addr <= imm < d_addr + d_size:
                        d_offset = imm - d_addr
                        # Read up to 1024 bytes of referenced data table
                        referenced_data[imm] = d_bytes[d_offset : d_offset + 1024]

            # Calls
            if insn.category == "call" and insn.referenced_address:
                calls.append(insn.referenced_address)

        # Calculate actual size
        actual_size = (instructions[-1].address + instructions[-1].size) - instructions[0].address

        func_ctx = FunctionContext(
            address=func_addr,
            name=func_name,
            size_bytes=actual_size,
            architecture=self.arch.value,
            instructions=instructions,
            basic_blocks=basic_blocks,
            cfg=cfg,
            constants=constants,
            referenced_data=referenced_data,
            calls=calls,
            opcode_stats=opcode_stats,
            category_stats=category_stats,
        )
        return func_ctx

    def _build_cfg(
        self,
        entry_addr: int,
        instructions: list[Instruction],
    ) -> tuple[list[BasicBlock], ControlFlowGraph]:
        """Partition instructions into basic blocks and build CFG."""
        if not instructions:
            cfg = ControlFlowGraph(entry_address=entry_addr)
            return [], cfg

        # Step 1: Identify leaders (entry points of basic blocks)
        leaders: set[int] = {instructions[0].address}
        insn_map = {insn.address: insn for insn in instructions}

        for i, insn in enumerate(instructions):
            if insn.is_branch():
                # Target of branch is a leader
                if insn.referenced_address and insn.referenced_address in insn_map:
                    leaders.add(insn.referenced_address)
                # Next instruction after branch is a leader
                if i + 1 < len(instructions):
                    leaders.add(instructions[i + 1].address)

        # Step 2: Form basic blocks
        blocks: dict[int, BasicBlock] = {}
        sorted_leaders = sorted(leaders)
        for i, l_addr in enumerate(sorted_leaders):
            next_l_addr = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else None
            block_insns = [
                insn for insn in instructions
                if l_addr <= insn.address and (next_l_addr is None or insn.address < next_l_addr)
            ]
            if block_insns:
                bb = BasicBlock(
                    start_address=block_insns[0].address,
                    end_address=block_insns[-1].address + block_insns[-1].size,
                    instructions=block_insns,
                    is_entry=(block_insns[0].address == entry_addr),
                    is_exit=any(insn.mnemonic in ("ret", "bx", "eret") for insn in block_insns),
                )
                blocks[bb.start_address] = bb

        # Step 3: Link edges between blocks
        edges: list[tuple[int, int]] = []
        for bb in blocks.values():
            if not bb.instructions:
                continue
            last_insn = bb.instructions[-1]

            # Direct branch or call
            if last_insn.is_branch():
                if last_insn.referenced_address and last_insn.referenced_address in blocks:
                    bb.successors.add(last_insn.referenced_address)
                    blocks[last_insn.referenced_address].predecessors.add(bb.start_address)
                    edges.append((bb.start_address, last_insn.referenced_address))

                # Conditional branch falls through to next sequential block
                if last_insn.mnemonic not in ("jmp", "b", "ret", "bx"):
                    next_addr = last_insn.address + last_insn.size
                    if next_addr in blocks:
                        bb.successors.add(next_addr)
                        blocks[next_addr].predecessors.add(bb.start_address)
                        edges.append((bb.start_address, next_addr))
            elif not bb.is_exit:
                # Fall-through to next block
                next_addr = last_insn.address + last_insn.size
                if next_addr in blocks:
                    bb.successors.add(next_addr)
                    blocks[next_addr].predecessors.add(bb.start_address)
                    edges.append((bb.start_address, next_addr))

        cfg = ControlFlowGraph(
            entry_address=entry_addr,
            blocks=blocks,
            edges=edges,
        )
        cfg.analyze_loops()

        return list(blocks.values()), cfg
