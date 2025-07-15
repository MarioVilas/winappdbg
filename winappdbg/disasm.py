#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2025, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""
Binary code disassembly.

**Disassembler loader:**

- :class:`Disassembler`
- :class:`Engine`

**Disassembler engines:**

- :class:`BeaEngine`
- :class:`CapstoneEngine`
- :class:`DistormEngine`
"""

from __future__ import with_statement

__all__ = [
    "Disassembler",
    "Engine",
    "BeaEngine",
    "CapstoneEngine",
    "DistormEngine",
    "MiasmEngine",
]

import logging
import warnings

from . import win32
from .textio import HexDump

# lazy imports
bea_disasm = None
distorm3 = None
capstone = None
miasm = None

# ==============================================================================


class Engine:
    """
    Base class for disassembly engine adaptors.

    :cvar str name: Engine name to use with the :class:`Disassembler` class.
    :cvar str desc: User friendly name of the disassembler engine.
    :cvar str url: Download URL.
    :cvar set(str) supported: Set of supported processor architectures.
        For more details see :attr:`winappdbg.win32.arch`.
    :ivar str arch: Name of the processor architecture.
    """

    name = "<insert engine name here>"
    desc = "<insert engine description here>"
    url = "<insert download url here>"
    supported = set()

    def __init__(self, arch=None):
        """
        :param str arch: Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see :attr:`winappdbg.win32.arch`.
        :raises NotImplementedError: This disassembler doesn't support the
            requested processor architecture.
        """
        self.arch = self._validate_arch(arch)
        try:
            self._import_dependencies()
        except ImportError:
            msg = "%s is not installed or can't be found. Download it from: %s"
            msg = msg % (self.name, self.url)
            raise NotImplementedError(msg)

    def _validate_arch(self, arch=None):
        """
        :param str arch: Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see :attr:`winappdbg.win32.arch`.
        :return: Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see :attr:`winappdbg.win32.arch`.
        :rtype: str
        :raises NotImplementedError: This disassembler doesn't support the
            requested processor architecture.
        """

        # Use the default architecture if none specified.
        if not arch:
            arch = win32.arch

        # Validate the architecture.
        if arch not in self.supported:
            msg = "The %s engine cannot decode %s code."
            msg = msg % (self.name, arch)
            raise NotImplementedError(msg)

        # Return the architecture.
        return arch

    @classmethod
    def _import_dependencies(cls):
        """
        Loads the dependencies for this disassembler.

        :raises ImportError: This disassembler cannot find or load the
            necessary dependencies to make it work.
        """
        raise SyntaxError("Subclasses MUST implement this method!")

    def decode(self, address, code):
        """
        :param int address: Memory address where the code was read from.
        :param str code: Machine code to disassemble.
        :return: List of tuples. Each tuple represents an assembly instruction
            and contains:
            - Memory address of instruction.
            - Size of instruction in bytes.
            - Disassembly line of instruction.
            - Hexadecimal dump of instruction.
        :rtype: list[tuple(int, int, str, str)]
        :raises NotImplementedError: This disassembler could not be loaded.
            This may be due to missing dependencies.
        """
        raise NotImplementedError()


# ==============================================================================


class BeaEngine(Engine):
    """
    Integration with the BeaEngine disassembler by Beatrix.
    """

    name = "BeaEngine"
    desc = "BeaEngine disassembler by Beatrix"
    url = "https://github.com/BeaEngine/beaengine"

    supported = set(
        (
            win32.ARCH_I386,
            win32.ARCH_AMD64,
        )
    )

    @classmethod
    def _import_dependencies(cls):
        global bea_disasm
        if bea_disasm is None:
            # Lazy import.
            from BeaEnginePython import Disasm

            bea_disasm = Disasm

    def __init__(self, arch=None):
        super().__init__(arch)
        if self.arch == win32.ARCH_I386:
            self._arch_code = 32
        else:
            self._arch_code = 64

    def decode(self, address, code):
        result = []
        try:
            # Try the latest BeaEngine API.
            instr = bea_disasm(code, address)
            instr.set_arch(self._arch_code)
            while instr.read() > 0:
                size = instr.len()
                disasm = instr.repr()
                dump = instr.bytes().hex()
                result.append((instr.addr(), size, disasm, dump))
        except TypeError:
            # This is a fallback for older versions of BeaEngine.
            # It's less efficient but should still work.
            result = []
            offset = 0
            while offset < len(code):
                try:
                    current_address = address + offset
                    instr = bea_disasm(code[offset:])
                    instr.set_arch(self._arch_code)
                    size = instr.read()
                    if size > 0:
                        disasm = instr.repr()
                        dump = instr.bytes().hex()
                        result.append((current_address, size, disasm, dump))
                        offset += size
                    else:
                        # Couldn't disassemble, treat as one byte.
                        dump = code[offset : offset + 1].hex()
                        disasm = "db 0x%s" % dump
                        result.append((current_address, 1, disasm, dump))
                        offset += 1
                except Exception:
                    # Couldn't disassemble, treat as one byte.
                    dump = code[offset : offset + 1].hex()
                    disasm = "db 0x%s" % dump
                    result.append((current_address, 1, disasm, dump))
                    offset += 1
        return result


# ==============================================================================


class DistormEngine(Engine):
    """
    Integration with the diStorm disassembler by Gil Dabah.
    """

    name = "diStorm"
    desc = "diStorm disassembler by Gil Dabah"
    url = "https://github.com/gdabah/distorm"

    supported = set(
        (
            win32.ARCH_I386,
            win32.ARCH_AMD64,
        )
    )

    @classmethod
    def _import_dependencies(cls):
        # Load the distorm bindings.
        global distorm3
        if distorm3 is None:
            import distorm3

    def __init__(self, arch=None):
        super().__init__(arch)

        # Load the decoder function.
        self.__decode = distorm3.Decode

        # Load the bits flag.
        self.__flag = {
            win32.ARCH_I386: distorm3.Decode32Bits,
            win32.ARCH_AMD64: distorm3.Decode64Bits,
        }[self.arch]

    def decode(self, address, code):
        return self.__decode(address, code, self.__flag)


# ==============================================================================


class CapstoneEngine(Engine):
    """
    Integration with the Capstone disassembler by Nguyen Anh Quynh.
    """

    name = "Capstone"
    desc = "Capstone disassembler by Nguyen Anh Quynh"
    url = "http://www.capstone-engine.org/"

    supported = set(
        (
            win32.ARCH_I386,
            win32.ARCH_AMD64,
            win32.ARCH_THUMB,
            win32.ARCH_ARM,
            win32.ARCH_ARM64,
        )
    )

    @classmethod
    def _import_dependencies(cls):
        # Load the Capstone bindings.
        global capstone
        if capstone is None:
            import capstone

    def __init__(self, arch=None):
        super().__init__(arch)

        # Load the constants for the requested architecture.
        self.__constants = {
            win32.ARCH_I386: (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            win32.ARCH_AMD64: (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            win32.ARCH_THUMB: (capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB),
            win32.ARCH_ARM: (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            win32.ARCH_ARM64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
        }

        # Test for the bug in early versions of Capstone.
        # If found, warn the user about it.
        try:
            self.__bug = not isinstance(
                list(
                    capstone.cs_disasm_quick(
                        capstone.CS_ARCH_X86, capstone.CS_MODE_32, b"\x90", 1
                    )
                )[0],
                capstone.capstone.CsInsn,
            )
        except AttributeError:
            self.__bug = False
        if self.__bug:
            warnings.warn(
                "This version of the Capstone bindings is unstable,"
                " please upgrade to a newer one!",
                RuntimeWarning,
                stacklevel=4,
            )

    def decode(self, address, code):
        # Get the constants for the requested architecture.
        arch, mode = self.__constants[self.arch]

        # Get the decoder function outside the loop.
        md = capstone.Cs(arch, mode)
        decoder = md.disasm_lite

        # If the buggy version of the bindings are being used, we need to catch
        # all exceptions broadly. If not, we only need to catch CsError.
        if self.__bug:
            CsError = Exception
        else:
            CsError = capstone.CsError

        # Create the variables for the instruction length, mnemonic and
        # operands. That way they won't be created within the loop,
        # minimizing the chances data might be overwritten.
        # This only makes sense for the buggy vesion of the bindings, normally
        # memory accesses are safe).
        length = mnemonic = op_str = None

        # For each instruction...
        result = []
        offset = 0
        while offset < len(code):
            # Disassemble a single instruction, because disassembling multiple
            # instructions may cause excessive memory usage (Capstone allocates
            # approximately 1K of metadata per each decoded instruction).
            instr = None
            try:
                instr = list(decoder(code[offset : offset + 64], address + offset, 1))[
                    0
                ]
            except IndexError:
                pass  # No instructions decoded.
            except CsError:
                pass  # Any other error.

            # On success add the decoded instruction.
            if instr is not None:
                # Get the instruction length, mnemonic and operands.
                # Copy the values quickly before someone overwrites them,
                # if using the buggy version of the bindings (otherwise it's
                # irrelevant in which order we access the properties).
                length = instr[1]
                mnemonic = instr[2]
                op_str = instr[3]

                # Concatenate the mnemonic and the operands.
                if op_str:
                    disasm = "%s %s" % (mnemonic, op_str)
                else:
                    disasm = mnemonic

                # Get the instruction bytes as a hexadecimal dump.
                hexdump = HexDump.hexadecimal(code[offset : offset + length])

            # On error add a "define constant" instruction.
            # The exact instruction depends on the architecture.
            else:
                # The number of bytes to skip depends on the architecture.
                # On Intel processors we'll skip one byte, since we can't
                # really know the instruction length. On the rest of the
                # architectures we always know the instruction length.
                if self.arch in (win32.ARCH_I386, win32.ARCH_AMD64):
                    length = 1
                else:
                    length = 4

                # Get the skipped bytes as a hexadecimal dump.
                skipped = code[offset : offset + length]
                hexdump = HexDump.hexadecimal(skipped)

                # Build the "define constant" instruction.
                # On Intel processors it's "db".
                # On ARM processors it's "dcb".
                if self.arch in (win32.ARCH_I386, win32.ARCH_AMD64):
                    mnemonic = "db "
                else:
                    mnemonic = "dcb "
                b = []
                for item in skipped:
                    if chr(item).isalpha():
                        b.append("'%s'" % chr(item))
                    else:
                        b.append("0x%x" % item)
                op_str = ", ".join(b)
                if mnemonic:
                    disasm = mnemonic + op_str
                else:
                    disasm = op_str

            # Add the decoded instruction to the list.
            result.append(
                (
                    address + offset,
                    length,
                    disasm,
                    hexdump,
                )
            )

            # Update the offset.
            offset += length

        # Return the list of decoded instructions.
        return result


# ==============================================================================


class MiasmEngine(Engine):
    """
    Integration with the Miasm disassembler by CEA-SEC.

    Note: All Miasm logging is disabled by default to prevent verbose warnings
    during disassembly. Users can control logging with the :meth:`set_logging` method.
    """

    name = "Miasm"
    desc = "Miasm disassembler by CEA-SEC"
    url = "https://github.com/cea-sec/miasm"

    supported = set(
        (
            win32.ARCH_I386,
            win32.ARCH_AMD64,
            win32.ARCH_ARM,
            win32.ARCH_ARM64,
            win32.ARCH_THUMB,
        )
    )

    @classmethod
    def _import_dependencies(cls):
        global miasm
        if miasm is None:
            import miasm.analysis.binary
            import miasm.analysis.machine
            import miasm.core.locationdb
            class MiasmModules:
                Container = miasm.analysis.binary.Container
                Machine = miasm.analysis.machine.Machine
                LocationDB = miasm.core.locationdb.LocationDB
            miasm = MiasmModules()
            cls.set_logging(False)

    @classmethod
    def set_logging(cls, enabled=True):
        """
        Enable or disable Miasm logging.

        :param bool enabled: Whether to enable Miasm logging.

        Example:
            # Enable Miasm logging.
            MiasmEngine.set_logging(True)

            # Disable all Miasm logging (default state).
            MiasmEngine.set_logging(False)
        """
        miasm_loggers = [
            # Core disassembly loggers.
            "asmblock", "cpuhelper",

            # Architecture-specific loggers.
            "aarch64dis", "x86_arch", "armdis", "mips32dis",
            "msp430dis", "ppcdis",

            # Analysis and processing loggers.
            "binary", "expr_reduce", "exprsimp", "symbexec",
            "analysis", "simplifier", "cst_propag",

            # JIT engine loggers.
            "jit_x86", "jit_arm", "jit_aarch64", "jit_mips32",
            "jit_msp430", "jit_ppc", "jit_mep",

            # Loader loggers.
            "loader_elf", "loader_pe", "loader_common",
            "jitload.py", "jit function call",

            # Parser loggers.
            "elfparse", "peparse", "pepy",

            # OS-specific loggers.
            "environment", "syscalls", "seh_helper", "win_api_x86_32",

            # Translator loggers..
            "translator_z3", "translator_smt2",

            # Semantic analysis loggers.
            "x86_sem",
        ]
        for logger_name in miasm_loggers:
            logger = logging.getLogger(logger_name)
            logger.disabled = not enabled

    def __init__(self, arch=None):
        super().__init__(arch)

        # Map WinAppDbg architectures to Miasm architecture names
        self._arch_map = {
            win32.ARCH_I386: "x86_32",
            win32.ARCH_AMD64: "x86_64",
            win32.ARCH_ARM: "arml",
            win32.ARCH_ARM64: "aarch64l",
            win32.ARCH_THUMB: "armtl",
        }

        # Get the Miasm architecture name
        self._miasm_arch = self._arch_map[self.arch]

    def decode(self, address, code):
        """
        Decode machine code using Miasm.

        :param int address: Memory address where the code was read from.
        :param str code: Machine code to disassemble.
        :return: List of tuples (address, size, disasm, hexdump)
        :rtype: list[tuple(int, int, str, str)]
        """
        result = []

        try:
            # Create location database
            loc_db = miasm.LocationDB()

            # Create container from raw bytes
            cont = miasm.Container.from_string(code, loc_db)

            # Create machine for the target architecture
            machine = miasm.Machine(self._miasm_arch)

            # Get disassembler engine
            mdis = machine.dis_engine(cont.bin_stream, loc_db=loc_db)

            # Disassemble each instruction
            offset = 0
            addr = address

            while offset < len(code):
                try:
                    # Disassemble one instruction
                    instr = mdis.dis_instr(offset)

                    if instr is not None:
                        # Extract instruction info
                        disasm = str(instr)
                        size = instr.l
                        hexdump = HexDump.hexadecimal(code[offset:offset + size])

                        result.append((addr, size, disasm, hexdump))
                        offset += size
                        addr += size
                    else:
                        # Fallback: treat as data
                        # The exact instruction depends on the architecture
                        if self.arch in (win32.ARCH_I386, win32.ARCH_AMD64):
                            size = 1
                            mnemonic = "db"
                        else:
                            size = 4
                            mnemonic = "dcb"

                        # Don't go beyond the code buffer
                        size = min(size, len(code) - offset)

                        # Get the data bytes
                        data_bytes = code[offset:offset + size]
                        hexdump = HexDump.hexadecimal(data_bytes)

                        # Build the "define constant" instruction
                        b = []
                        for byte in data_bytes:
                            if isinstance(byte, int):
                                char_val = byte
                            else:
                                char_val = ord(byte)

                            if 32 <= char_val <= 126:  # printable ASCII
                                b.append("'%s'" % chr(char_val))
                            else:
                                b.append("0x%02x" % char_val)

                        disasm = "%s %s" % (mnemonic, ", ".join(b))

                        result.append((addr, size, disasm, hexdump))
                        offset += size
                        addr += size

                except Exception:
                    # Final fallback: single byte
                    if offset < len(code):
                        size = 1
                        data_bytes = code[offset:offset + size]
                        hexdump = HexDump.hexadecimal(data_bytes)

                        byte_val = data_bytes[0]
                        if isinstance(byte_val, int):
                            char_val = byte_val
                        else:
                            char_val = ord(byte_val)

                        if 32 <= char_val <= 126:  # printable ASCII
                            disasm = "db '%s'" % chr(char_val)
                        else:
                            disasm = "db 0x%02x" % char_val

                        result.append((addr, size, disasm, hexdump))
                        offset += size
                        addr += size
                    else:
                        break

        except Exception:
            # Ultimate fallback: treat entire code as data
            if code:
                hexdump = HexDump.hexadecimal(code)
                disasm = "db %s" % ", ".join("0x%02x" % (b if isinstance(b, int) else ord(b)) for b in code)
                result.append((address, len(code), disasm, hexdump))

        return result


# ==============================================================================

# TODO: use a lock to access __decoder
# TODO: look in sys.modules for whichever disassembler is already loaded


class Disassembler:
    """
    Generic disassembler. Uses a set of adapters to decide which library to
    load for which supported platform.

    :cvar tuple(Engine) engines: Set of supported engines. If you implement your
        own adapter you can add its class here to make it available to
        :class:`Disassembler`.
    """

    # These are the supported disassembly engines.
    engines = (
        MiasmEngine,        # https://github.com/cea-sec/miasm
        CapstoneEngine,     # https://github.com/capstone-engine/capstone
        DistormEngine,      # https://github.com/gdabah/distorm
        BeaEngine,          # https://github.com/BeaEngine/beaengine
    )

    # Add the list of implemented disassembler adaptors to the docstring.
    __doc__ += "\n"
    for e in engines:
        __doc__ += "         - %s - %s (%s)\n" % (e.name, e.desc, e.url)
    del e

    # Cache of already loaded disassemblers.
    __decoder = {}

    def __new__(cls, arch=None, engine=None):
        """
        Factory class. You can't really instance a :class:`Disassembler`
        object, instead one of the adapter :class:`Engine` subclasses is
        returned.

        :param str arch: (Optional) Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see :attr:`winappdbg.win32.arch`.
        :param str engine: (Optional) Name of the disassembler engine.
            If not provided a compatible one is loaded automatically.
            See: :attr:`Engine.name`
        :raises NotImplementedError: No compatible disassembler was found that
            could decode machine code for the requested architecture. This may
            be due to missing dependencies.
        :raises ValueError: An unknown engine name was supplied.
        """

        # Use the default architecture if none specified.
        if not arch:
            arch = win32.arch

        # Return a compatible engine if none specified.
        if not engine:
            found = False
            for clazz in cls.engines:
                try:
                    if arch in clazz.supported:
                        selected = (clazz.name, arch)
                        try:
                            decoder = cls.__decoder[selected]
                        except KeyError:
                            decoder = clazz(arch)
                            cls.__decoder[selected] = decoder
                        return decoder
                except NotImplementedError:
                    pass
            msg = "No disassembler engine available for %s code." % arch
            raise NotImplementedError(msg)

        # Return the specified engine.
        selected = (engine, arch)
        try:
            decoder = cls.__decoder[selected]
        except KeyError:
            found = False
            engineLower = engine.lower()
            for clazz in cls.engines:
                if clazz.name.lower() == engineLower:
                    found = True
                    break
            if not found:
                msg = "Unsupported disassembler engine: %s" % engine
                raise ValueError(msg)
            if arch not in clazz.supported:
                msg = "The %s engine cannot decode %s code." % selected
                raise NotImplementedError(msg)
            decoder = clazz(arch)
            cls.__decoder[selected] = decoder
        return decoder

    @classmethod
    def get_all_engines(cls):
        """
        Get the full list of available disassembly engines
        for this version of WinAppDbg.

        To get the disassembly engines that can actually be used, call
        :meth:`get_supported_engines` instead.

        :return: Tuple of Engine objects.
        :rtype: tuple(Engine)
        """
        return cls.engines

    @classmethod
    def get_available_engines(cls):
        """
        Get the list of supported disassembly engines on this machine.

        To get the full list of disassembly engines supported by this version
        of WinAppDbg, call :meth:`get_all_engines` instead.

        .. warning:: This call will internally load all the required
           dependencies for all disassembly engines! This is to ensure they are
           available.

        :return: Tuple of Engine objects.
        :rtype: tuple(Engine)
        """
        supported = []
        for e in cls.engines:
            try:
                e._import_dependencies()
                supported.append(e)
            except Exception:
                pass
        return tuple(supported)
