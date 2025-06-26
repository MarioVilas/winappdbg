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

from winappdbg import Color

# Can we use colors?
if Color.can_use_colors():

    # Let's be polite: put everything in a try/except block
    # so we can reset the console colors before quitting.
    try:

        # Set black background.
        Color.bk_black()

        # For each color...
        for color in ( "red", "green", "blue", "cyan", "magenta", "yellow", "white" ):

            # Set the color.
            function = getattr( Color, color )
            function()

            # For each intensity...
            for intensity in ( "light", "dark" ):

                # Set the intensity.
                function = getattr( Color, intensity )
                function()

                # Print a message.
                print("This is %s %s text on black background." % (intensity, color))

        # Set black text.
        Color.black()

        # For each color...
        for color in ( "red", "green", "blue", "cyan", "magenta", "yellow", "white" ):

            # Set the background color.
            function = getattr( Color, "bk_" + color )
            function()

            # For each intensity...
            for intensity in ( "light", "dark" ):

                # Set the background intensity.
                function = getattr( Color, "bk_" + intensity )
                function()

                # Print a message.
                print("This is black text on %s %s background." % (intensity, color))

    # Reset the console colors and quit.
    finally:
        Color.reset()

# No colors available!
else:
    print("Can't use colors! Are you redirecting the output to a file?")
