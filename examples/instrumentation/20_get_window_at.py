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

# $Id$

from winappdbg import System, HexDump
import sys

try:

    # Get the coordinates from the command line.
    x = int( sys.argv[1] )
    y = int( sys.argv[2] )

    # Get the window at the requested position.
    window   = System.get_window_at( x, y )

    # Get the window coordinates.
    rect     = window.get_screen_rect()
    position = (rect.left, rect.top, rect.right, rect.bottom)
    size     = (rect.right - rect.left, rect.bottom - rect.top)

    # Print the window information.
    print "Handle:   %s" % HexDump.integer( window.get_handle() )
    print "Caption:  %s" % window.text
    print "Class:    %s" % window.classname
    print "Style:    %s" % HexDump.integer( window.style )
    print "ExStyle:  %s" % HexDump.integer( window.exstyle )
    print "Position: (%i, %i) - (%i, %i)" % position
    print "Size:     (%i, %i)" % size

except WindowsError:
    print "No window at those coordinates!"
