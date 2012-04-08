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

__all__ = ['Disassembler', 'DistormEngine']

import win32

import warnings

# lazy imports
distorm3 = None
r_asm = None

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
    name = "distorm"
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

##class RadareEngine (Engine):
##    name = "radare"
##    desc = "Radare2 by Pancake (https://twitter.com/trufae)"
##    url  = "http://radare.org/get/"
##
##    supported = set((
##        win32.ARCH_I386,
##        win32.ARCH_AMD64,
##        win32.ARCH_ARM,
##        win32.ARCH_MIPS,
##        win32.ARCH_PPC,
##        win32.ARCH_SHX,
##        win32.ARCH_SPARC,
##    ))
##
##    def __init__(self, arch = None):
##
##        # Use the default architecture if none specified.
##        if not arch:
##            arch = win32.arch
##
##        # Validate the architecture.
##        if arch not in self.supported:
##            msg = "The %s engine cannot decode %s code."
##            msg = msg % (self.name, arch)
##            raise NotImplementedError(msg)
##
##        # Load the distorm bindings.
##        global r_asm
##        if r_asm is None:
##            try:
##                from r2 import r_asm
##            except ImportError:
##                msg = ("%s is not installed or can't be found. "
##                "Download it from: %s" % (self.name, self.url))
##                raise NotImplementedError(msg)
##
##        # Load the decoder object.
##        rasm = r_asm.RAsm()
##        rasm.use({
##            win32.ARCH_I386:    'x86.olly',
##            win32.ARCH_AMD64:   'x86.udis86',
##            win32.ARCH_ARM:     'arm',
##            win32.ARCH_MIPS:    'mips',
##            win32.ARCH_PPC:     'ppc',
##            win32.ARCH_SHX:     'sh',
##            win32.ARCH_SPARC:   'sparc',
##        }[arch])
##        self.__rasm = rasm
##
##    def decode(self, address, code):
##        return self.__rasm.mdisassemble(code)

#==============================================================================

# TODO: use a lock to access __decoder

class Disassembler (object):

    engines = (
        DistormEngine,
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
