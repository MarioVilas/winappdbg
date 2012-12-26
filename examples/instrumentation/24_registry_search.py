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

import sys

# $Id$

from winappdbg import System, Color

def reg_search( search ):

    # Show the user what we're searching for.
    print "Searching for: %r" % search

    # For each Registry key...
    for path in System.registry.iterkeys():

        # Try to open the key. On error skip it.
        try:
            key = System.registry[ path ]
        except Exception:
            continue

        # Get the default value. On error skip it.
        try:
            default = str(key)
        except KeyError:
            default = ""
        except Exception:
            continue

        # Does the default value match?
        if search in default:
            text = "%s\\@: %s" % ( path, default )
            highlight( search, text )

        # Does the key match?
        elif search in path[ path.rfind("\\") : ]:
            highlight( search, path )

        # For each Registry value...
        for name in key.iterkeys():

            # Try to get the value. On error ignore it.
            try:
                value = key[name]
            except Exception:
                value = ""

            # Registry values can be of many data types.
            # For this search we need to force all values to be strings.
            if type(value) not in (str, unicode):
                value = str(value)

            # Do the name or value match?
            if search in name or search in value:
                text = "%s\\%s: %r" % ( path, name, value )
                highlight( search, text )

# Helper function to print text with a highlighted search string.
def highlight( search, text ):
    # ...
    if can_highlight:
        Color.default()
        p = 0
        t = len( text )
        s = len( search )
        while p < t:
            q = text.find( search )
            if q < p:
                q = t
            sys.stdout.write( text[ p : q ] )
            Color.red()
            Color.bright()
            sys.stdout.write( text[ q : q + s ] )
            Color.default()
            sys.stdout.write("\r\n")
            p = q + s
    else:
        print text

# Determine if the output is a console or a file.
# Trying to use colors fails if the output is not the console.
can_highlight = Color.can_use_colors()

# When invoked from the command line,
# the first argument is a search string.
if __name__ == "__main__":
    import sys
    search = sys.argv[1]
    reg_search( search )
