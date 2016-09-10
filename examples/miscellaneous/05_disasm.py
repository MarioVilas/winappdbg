#!/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2016, Mario Vilas
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

from sys import argv

from winappdbg import Disassembler, HexInput, CrashDump

# If there are no command line arguments...
if len( argv ) == 1:

    # Show the help message.
    print "Usage:"
    print "  %s <file> [offset] [size] [arch] [engine]" % argv[0]

    # Show the available disassembler engines.
    print
    print "Supported disassembler engines:"
    print "-------------------------------"
    available = Disassembler.get_available_engines()
    for engine in Disassembler.get_all_engines():
        print
        print "Name: %s" % engine.name
        print "Description: %s" % engine.desc
        print "Available: %s" % ("YES" if engine in available else "NO")
        print "Supported architectures: %s" % ", ".join( engine.supported )

# If there are command line arguments...
else:

    # Get the arguments from the command line.
    filename = argv[1]
    try:
        offset = HexInput.address( argv[2] )
    except IndexError:
        offset = 0
    try:
        size = HexInput.integer( argv[3] )
    except IndexError:
        size = 0
    try:
        arch = argv[4]
    except IndexError:
        arch = None
    try:
        engine = argv[5]
    except IndexError:
        engine = None

    # Load the requested disassembler engine.
    disasm = Disassembler( arch, engine )

    # Load the binary code.
    with open( filename, 'rb' ) as fd:
        fd.seek( offset )
        if size:
            code = fd.read( size )
        else:
            code = fd.read()

    # Disassemble the code.
    disassembly = disasm.decode( offset, code )

    # Show the disassembly.
    print CrashDump.dump_code( disassembly, offset )
