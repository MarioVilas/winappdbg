#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2015, Mario Vilas
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


def find_window():

    # If two arguments are given, the first is the classname
    # and the second is the caption text.
    if len(sys.argv) > 2:
        classname = sys.argv[1]
        caption   = sys.argv[2]
        if not classname:
            classname = None
        if not caption:
            caption   = None
        window = System.find_window( classname, caption )

    # If only one argument is given, try the caption text, then the classname.
    else:
        try:
            window = System.find_window( windowName = sys.argv[1] )
        except WindowsError:
            window = System.find_window( className = sys.argv[1] )

    return window


def show_window( window ):

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


# ...begins just like the previous example...


def user_confirmed():
    print
    answer = raw_input( "Are you sure you want to kill this program? (y/N):" )
    answer = answer.strip().upper()
    return answer.startswith("Y")


def main():

    # Find the window.
    try:
        window = find_window()
    except WindowsError:
        print "No window found!"
        return

    # Show the window info to the user.
    show_window( window )

    # Ask the user for confirmation.
    if user_confirmed():

        # Kill the program.
        window.kill()


if __name__ == '__main__':
    main()
