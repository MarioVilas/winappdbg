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

#==============================================================================

class Engine (object):
    name = "<insert engine name here>"
    supports = set()

    def __init__(self, arch = None):
        raise NotImplementedError()

    def decode(self, address, code):
        raise NotImplementedError()

#==============================================================================

class DistormEngine (Engine):
    name = "diStorm"
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
                    msg = ("diStorm is not installed or can't be found. "
                    "Download it from: " % self.url)
                    warnings.warn(msg, RuntimeWarning)  # XXX HACK
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

# TODO: use a lock to access __decoder

class Disassembler (object):

    engines = {
        'distorm' : DistormEngine,
    }

    # Cache of already loaded disassemblers.
    __decoder = {}

    def __new__(cls, arch = None, engine = None):

        # Use the default architecture if none specified.
        if not arch:
            arch = win32.arch

        # Return a compatible engine if none specified.
        if not engine:
            found = False
            for engine, clazz in cls.engines.iteritems():
                try:
                    if arch in clazz.supported:
                        selected = (engine, arch)
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
            try:
                clazz = cls.engines[engine]
            except KeyError:
                msg = "Unsupported disassembler engine: %s" % engine
                raise NotImplementedError(msg)
            if arch not in clazz.supported:
                msg = "The %s engine cannot decode %s code." % selected
                raise NotImplementedError(msg)
            decoder = clazz(arch)
            cls.__decoder[selected] = decoder
        return decoder
