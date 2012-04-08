#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2012, Mario Vilas
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
"""

__revision__ = "$Id$"

__all__ = ['Disassembler', 'DistormEngine', 'BeaEngine']

from textio import HexDump
import win32

import ctypes
import warnings

# lazy imports
distorm3 = None
BeaEnginePython = None

#==============================================================================

class Engine (object):
    name = "<insert engine name here>"
    desc = "<insert engine description here>"
    url  = "<insert download url here>"
    supports = set()

    def __init__(self, arch = None):
        raise NotImplementedError()

    def decode(self, address, code):
        raise NotImplementedError()

#==============================================================================

class DistormEngine (Engine):
    name = "diStorm"
    desc = "diStorm disassembler by Gil Dabah"
    url  = "https://code.google.com/p/distorm3"

    supported = set((
        win32.ARCH_I386,
        win32.ARCH_AMD64,
    ))

    def __init__(self, arch = None):

        # Use the default architecture if none specified.
        if not arch:
            arch = win32.arch

        # Validate the architecture.
        if arch not in self.supported:
            msg = "The %s engine cannot decode %s code."
            msg = msg % (self.name, arch)
            raise NotImplementedError(msg)

        # Load the distorm bindings.
        global distorm3
        if distorm3 is None:
            try:
                import distorm3
            except ImportError:
                try:
                    import distorm as distorm3
                except ImportError:
                    msg = ("%s is not installed or can't be found. "
                    "Download it from: %s" % (self.name, self.url))
                    raise NotImplementedError(msg)

        # Load the decoder function.
        self.__decode = distorm3.Decode

        # Load the bits flag.
        self.__flag = {
            win32.ARCH_I386:  distorm3.Decode32Bits,
            win32.ARCH_AMD64: distorm3.Decode64Bits,
        }[arch]

    def decode(self, address, code):
        return self.__decode(address, code, self.__flag)

#==============================================================================

class BeaEngine (Engine):
    name = "BeaEngine"
    desc = "BeaEngine disassembler by Beatrix"
    url  = "https://sourceforge.net/projects/winappdbg/files/additional%20packages/BeaEngine/"

    supported = set((
        win32.ARCH_I386,
        win32.ARCH_AMD64,
    ))

    def __init__(self, arch = None):

        # Use the default architecture if none specified.
        if not arch:
            arch = win32.arch

        # Remember the architecture.
        self.arch = arch

        # Validate the architecture.
        if arch not in self.supported:
            msg = "The %s engine cannot decode %s code."
            msg = msg % (self.name, arch)
            raise NotImplementedError(msg)

        # Load the BeaEngine ctypes wrapper.
        global BeaEnginePython
        if BeaEnginePython is None:
            try:
                import BeaEnginePython
            except ImportError:
                msg = ("%s is not installed or can't be found. "
                "Download it from: %s" % (self.name, self.url))
                raise NotImplementedError(msg)

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
            Instruction.Archi = 1
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
                for offset in xrange(offset, offset + len(code)):
                    char = "%.2X" % ord(buffer[offset])
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

# TODO: use a lock to access __decoder

class Disassembler (object):

    engines = (
        DistormEngine,
        BeaEngine,
    )

    # Cache of already loaded disassemblers.
    __decoder = {}

    def __new__(cls, arch = None, engine = None):

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
                            try:
                                decoder = clazz(arch)
                            except ImportError:
                                msg = ("%s is not installed or can't be found."
                                       " Download it from: ")
                                msg = msg % (clazz.name, clazz.url)
                                raise NotImplementedError(msg)
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
                raise NotImplementedError(msg)
            if arch not in clazz.supported:
                msg = "The %s engine cannot decode %s code." % selected
                raise NotImplementedError(msg)
            decoder = clazz(arch)
            cls.__decoder[selected] = decoder
        return decoder
