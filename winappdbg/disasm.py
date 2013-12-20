#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2014, Mario Vilas
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

@group Disassembler loader:
    Disassembler, Engine

@group Disassembler engines:
    BeaEngine, CapstoneEngine, DistormEngine,
    LibdisassembleEngine, PyDasmEngine
"""

from __future__ import with_statement

__revision__ = "$Id$"

__all__ = [
    'Disassembler',
    'Engine',
    'BeaEngine',
    'CapstoneEngine',
    'DistormEngine',
    'LibdisassembleEngine',
    'PyDasmEngine',
]

from textio import HexDump
import win32

import ctypes
import warnings

# lazy imports
BeaEnginePython = None
distorm3 = None
pydasm = None
libdisassemble = None
capstone = None

#==============================================================================

class Engine (object):
    """
    Base class for disassembly engine adaptors.

    @type name: str
    @cvar name: Engine name to use with the L{Disassembler} class.

    @type desc: str
    @cvar desc: User friendly name of the disassembler engine.

    @type url: str
    @cvar url: Download URL.

    @type supported: set(str)
    @cvar supported: Set of supported processor architectures.
        For more details see L{win32.version._get_arch}.

    @type arch: str
    @ivar arch: Name of the processor architecture.
    """

    name = "<insert engine name here>"
    desc = "<insert engine description here>"
    url  = "<insert download url here>"
    supported = set()

    def __init__(self, arch = None):
        """
        @type  arch: str
        @param arch: Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see L{win32.version._get_arch}.

        @raise NotImplementedError: This disassembler doesn't support the
            requested processor architecture.
        """
        self.arch = self._validate_arch(arch)
        try:
            self._import_dependencies()
        except ImportError:
            msg = "%s is not installed or can't be found. Download it from: %s"
            msg = msg % (self.name, self.url)
            raise NotImplementedError(msg)

    def _validate_arch(self, arch = None):
        """
        @type  arch: str
        @param arch: Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see L{win32.version._get_arch}.

        @rtype:  str
        @return: Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see L{win32.version._get_arch}.

        @raise NotImplementedError: This disassembler doesn't support the
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

    def _import_dependencies(self):
        """
        Loads the dependencies for this disassembler.

        @raise ImportError: This disassembler cannot find or load the
            necessary dependencies to make it work.
        """
        raise SyntaxError("Subclasses MUST implement this method!")

    def decode(self, address, code):
        """
        @type  address: int
        @param address: Memory address where the code was read from.

        @type  code: str
        @param code: Machine code to disassemble.

        @rtype:  list of tuple( long, int, str, str )
        @return: List of tuples. Each tuple represents an assembly instruction
            and contains:
             - Memory address of instruction.
             - Size of instruction in bytes.
             - Disassembly line of instruction.
             - Hexadecimal dump of instruction.

        @raise NotImplementedError: This disassembler could not be loaded.
            This may be due to missing dependencies.
        """
        raise NotImplementedError()

#==============================================================================

class BeaEngine (Engine):
    """
    Integration with the BeaEngine disassembler by Beatrix.

    @see: U{https://sourceforge.net/projects/winappdbg/files/additional%20packages/BeaEngine/}
    """

    name = "BeaEngine"
    desc = "BeaEngine disassembler by Beatrix"
    url  = "https://sourceforge.net/projects/winappdbg/files/additional%20packages/BeaEngine/"

    supported = set((
        win32.ARCH_I386,
        win32.ARCH_AMD64,
    ))

    def _import_dependencies(self):

        # Load the BeaEngine ctypes wrapper.
        global BeaEnginePython
        if BeaEnginePython is None:
            import BeaEnginePython

    def decode(self, address, code):
        addressof = ctypes.addressof

        # Instance the code buffer.
        buffer = ctypes.create_string_buffer(code)
        buffer_ptr = addressof(buffer)

        # Instance the disassembler structure.
        Instruction = BeaEnginePython.DISASM()
        Instruction.VirtualAddr = address
        Instruction.EIP = buffer_ptr
        Instruction.SecurityBlock = buffer_ptr + len(code)
        if self.arch == win32.ARCH_I386:
            Instruction.Archi = 0
        else:
            Instruction.Archi = 0x40
        Instruction.Options = ( BeaEnginePython.Tabulation      +
                                BeaEnginePython.NasmSyntax      +
                                BeaEnginePython.SuffixedNumeral +
                                BeaEnginePython.ShowSegmentRegs )

        # Prepare for looping over each instruction.
        result = []
        Disasm = BeaEnginePython.Disasm
        InstructionPtr = addressof(Instruction)
        hexdump = HexDump.hexadecimal
        append = result.append
        OUT_OF_BLOCK   = BeaEnginePython.OUT_OF_BLOCK
        UNKNOWN_OPCODE = BeaEnginePython.UNKNOWN_OPCODE

        # For each decoded instruction...
        while True:

            # Calculate the current offset into the buffer.
            offset = Instruction.EIP - buffer_ptr

            # If we've gone past the buffer, break the loop.
            if offset >= len(code):
                break

            # Decode the current instruction.
            InstrLength = Disasm(InstructionPtr)

            # If BeaEngine detects we've gone past the buffer, break the loop.
            if InstrLength == OUT_OF_BLOCK:
                break

            # The instruction could not be decoded.
            if InstrLength == UNKNOWN_OPCODE:

                # Output a single byte as a "db" instruction.
                char = "%.2X" % ord(buffer[offset])
                result.append((
                    Instruction.VirtualAddr,
                    1,
                    "db %sh" % char,
                    char,
                ))
                Instruction.VirtualAddr += 1
                Instruction.EIP += 1

            # The instruction was decoded but reading past the buffer's end.
            # This can happen when the last instruction is a prefix without an
            # opcode. For example: decode(0, '\x66')
            elif offset + InstrLength > len(code):

                # Output each byte as a "db" instruction.
                for char in buffer[ offset : offset + len(code) ]:
                    char = "%.2X" % ord(char)
                    result.append((
                        Instruction.VirtualAddr,
                        1,
                        "db %sh" % char,
                        char,
                    ))
                    Instruction.VirtualAddr += 1
                    Instruction.EIP += 1

            # The instruction was decoded correctly.
            else:

                # Output the decoded instruction.
                append((
                    Instruction.VirtualAddr,
                    InstrLength,
                    Instruction.CompleteInstr.strip(),
                    hexdump(buffer.raw[offset:offset+InstrLength]),
                ))
                Instruction.VirtualAddr += InstrLength
                Instruction.EIP += InstrLength

        # Return the list of decoded instructions.
        return result

#==============================================================================

class DistormEngine (Engine):
    """
    Integration with the diStorm disassembler by Gil Dabah.

    @see: U{https://code.google.com/p/distorm3}
    """

    name = "diStorm"
    desc = "diStorm disassembler by Gil Dabah"
    url  = "https://code.google.com/p/distorm3"

    supported = set((
        win32.ARCH_I386,
        win32.ARCH_AMD64,
    ))

    def _import_dependencies(self):

        # Load the distorm bindings.
        global distorm3
        if distorm3 is None:
            try:
                import distorm3
            except ImportError:
                import distorm as distorm3

        # Load the decoder function.
        self.__decode = distorm3.Decode

        # Load the bits flag.
        self.__flag = {
            win32.ARCH_I386:  distorm3.Decode32Bits,
            win32.ARCH_AMD64: distorm3.Decode64Bits,
        }[self.arch]

    def decode(self, address, code):
        return self.__decode(address, code, self.__flag)

#==============================================================================

class PyDasmEngine (Engine):
    """
    Integration with PyDasm: Python bindings to libdasm.

    @see: U{https://code.google.com/p/libdasm/}
    """

    name = "PyDasm"
    desc = "PyDasm: Python bindings to libdasm"
    url  = "https://code.google.com/p/libdasm/"

    supported = set((
        win32.ARCH_I386,
    ))

    def _import_dependencies(self):

        # Load the libdasm bindings.
        global pydasm
        if pydasm is None:
            import pydasm

    def decode(self, address, code):

        # Decode each instruction in the buffer.
        result = []
        offset = 0
        while offset < len(code):

            # Try to decode the current instruction.
            instruction = pydasm.get_instruction(code[offset:offset+32],
                                                 pydasm.MODE_32)

            # Get the memory address of the current instruction.
            current = address + offset

            # Illegal opcode or opcode longer than remaining buffer.
            if not instruction or instruction.length + offset > len(code):
                hexdump = '%.2X' % ord(code[offset])
                disasm  = 'db 0x%s' % hexdump
                ilen    = 1

            # Correctly decoded instruction.
            else:
                disasm  = pydasm.get_instruction_string(instruction,
                                                        pydasm.FORMAT_INTEL,
                                                        current)
                ilen    = instruction.length
                hexdump = HexDump.hexadecimal(code[offset:offset+ilen])

            # Add the decoded instruction to the list.
            result.append((
                current,
                ilen,
                disasm,
                hexdump,
            ))

            # Move to the next instruction.
            offset += ilen

        # Return the list of decoded instructions.
        return result

#==============================================================================

class LibdisassembleEngine (Engine):
    """
    Integration with Immunity libdisassemble.

    @see: U{http://www.immunitysec.com/resources-freesoftware.shtml}
    """

    name = "Libdisassemble"
    desc = "Immunity libdisassemble"
    url  = "http://www.immunitysec.com/resources-freesoftware.shtml"

    supported = set((
        win32.ARCH_I386,
    ))

    def _import_dependencies(self):

        # Load the libdisassemble module.
        # Since it doesn't come with an installer or an __init__.py file
        # users can only install it manually however they feel like it,
        # so we'll have to do a bit of guessing to find it.

        global libdisassemble
        if libdisassemble is None:
            try:

                # If installed properly with __init__.py
                import libdisassemble.disassemble as libdisassemble

            except ImportError:

                # If installed by just copying and pasting the files
                import disassemble as libdisassemble

    def decode(self, address, code):

        # Decode each instruction in the buffer.
        result = []
        offset = 0
        while offset < len(code):

            # Decode the current instruction.
            opcode  = libdisassemble.Opcode( code[offset:offset+32] )
            length  = opcode.getSize()
            disasm  = opcode.printOpcode('INTEL')
            hexdump = HexDump.hexadecimal( code[offset:offset+length] )

            # Add the decoded instruction to the list.
            result.append((
                address + offset,
                length,
                disasm,
                hexdump,
            ))

            # Move to the next instruction.
            offset += length

        # Return the list of decoded instructions.
        return result

#==============================================================================

class CapstoneEngine (Engine):
    """
    Integration with the Capstone disassembler by Nguyen Anh Quynh.

    @see: U{http://www.capstone-engine.org/}
    """

    name = "Capstone"
    desc = "Capstone disassembler by Nguyen Anh Quynh"
    url  = "http://www.capstone-engine.org/"

    supported = set((
        win32.ARCH_I386,
        win32.ARCH_AMD64,
        ##win32.ARCH_ARM,
        ##win32.ARCH_ARM64,
        ##win32.ARCH_MIPS,
    ))

    BYTES_TO_SKIP = {
        win32.ARCH_I386:  1,
        win32.ARCH_AMD64: 1,
        ##win32.ARCH_ARM:   4,
        ##win32.ARCH_ARM64: 8,
        ##win32.ARCH_MIPS:  4,
    }

    def _import_dependencies(self):

        # Load the Capstone bindings.
        global capstone
        if capstone is None:
            import capstone

        # Load the constants for the requested architecture.
        self.__constants = {
            win32.ARCH_I386:  (capstone.CS_ARCH_X86,   capstone.CS_MODE_32),
            win32.ARCH_AMD64: (capstone.CS_ARCH_X86,   capstone.CS_MODE_64),
            ##win32.ARCH_ARM:   (capstone.CS_ARCH_ARM,   capstone.CS_MODE_ARM),
            ##win32.ARCH_ARM64: (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
            ##win32.ARCH_MIPS:  (capstone.CS_ARCH_MIPS,  0),
        }

        # Load the decoder function.
        self.__decoder = capstone.cs_disasm_quick


    def decode(self, address, code):

        # Get the constants for the requested architecture.
        arch, mode = self.__constants[self.arch]

        # For each instruction...
        result = []
        offset = 0
        while offset < len(code):

            # Disassemble a single instruction, because disassembling multiple
            # instructions causes segmentation faults sometimes in the first
            # published version of Capstone's bindings. We also need to catch
            # all exceptions broadly because of a syntax error in capstone.py
            # (same version of the bindings) when trying to raise CsError.
            try:
                instr = self.__decoder(
                    arch, mode, code[offset:offset+16], address+offset, 1)[0]
            except Exception:
                instr = None

            # On success add the decoded instruction.
            if instr is not None:

                # Get the instruction size.
                length = instr.size

                # Get the mnemonic and operands as a human readable string.
                disasm = "%s %s" % (instr.mnemonic, instr.op_str)

                # Get the instruction bytes as a hexadecimal dump.
                hexdump = HexDump.hexadecimal( code[offset:offset+length] )

            # On error add a "db" instruction.
            else:

                # The number of bytes to skip depends on the architecture.
                length = self.BYTES_TO_SKIP[self.arch]

                # Build the "db" instruction.
                bytes = []
                for i in xrange(offset, offset + length):
                    bytes.append("0x%.2x" % ord(code[i:i+1]))
                disasm = "db " + ", ".join(bytes)

                # Get the skipped bytes as a hexadecimal dump.
                hexdump = HexDump.hexadecimal( code[offset:offset+length] )

            # Add the decoded instruction to the list.
            result.append((
                address + offset,
                length,
                disasm,
                hexdump,
            ))

            # Update the offset.
            offset += length

        # Return the list of decoded instructions.
        return result

#==============================================================================

# TODO: use a lock to access __decoder
# TODO: look in sys.modules for whichever disassembler is already loaded

class Disassembler (object):
    """
    Generic disassembler. Uses a set of adapters to decide which library to
    load for which supported platform.

    @type engines: tuple( L{Engine} )
    @cvar engines: Set of supported engines. If you implement your own adapter
        you can add its class here to make it available to L{Disassembler}.
        Supported disassemblers are:
    """

    engines = (
        DistormEngine,  # diStorm engine goes first for backwards compatibility
        BeaEngine,
        PyDasmEngine,
        LibdisassembleEngine,
        CapstoneEngine,
    )

    # Add the list of supported disassemblers to the docstring.
    __doc__ += "\n"
    for e in engines:
        __doc__ += "         - %s - %s (U{%s})\n" % (e.name, e.desc, e.url)
    del e

    # Cache of already loaded disassemblers.
    __decoder = {}

    def __new__(cls, arch = None, engine = None):
        """
        Factory class. You can't really instance a L{Disassembler} object,
        instead one of the adapter L{Engine} subclasses is returned.

        @type  arch: str
        @param arch: (Optional) Name of the processor architecture.
            If not provided the current processor architecture is assumed.
            For more details see L{win32.version._get_arch}.

        @type  engine: str
        @param engine: (Optional) Name of the disassembler engine.
            If not provided a compatible one is loaded automatically.
            See: L{Engine.name}

        @raise NotImplementedError: No compatible disassembler was found that
            could decode machine code for the requested architecture. This may
            be due to missing dependencies.

        @raise ValueError: An unknown engine name was supplied.
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
                except NotImplementedError, e:
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
