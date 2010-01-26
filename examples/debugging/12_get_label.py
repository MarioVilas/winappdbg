#!~/.wine/drive_c/Python25/python.exe

# Copyright (c) 2009-2010, Mario Vilas
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

# Example #12
# http://apps.sourceforge.net/trac/winappdbg/wiki/Debugging#Example12:gettingthelabelforagivenmemoryaddress

from winappdbg import System, Process

def print_label( pid, address ):

    # Request debug privileges
    System.request_debug_privileges()

    # Instance a Process object
    process = Process( pid )

    # Lookup it's modules
    process.scan_modules()

    # Resolve the requested label address
    label = process.get_label_at_address( address )

    # Print the label
    print "%s == 0x%.08x" % ( label, address )

# When invoked from the command line,
# the first argument is a process ID,
# the second argument is a remote pointer (in hexadecimal)
if __name__ == "__main__":
    import sys
    pid     = int( sys.argv[1] )
    address = int( sys.argv[2], 0x10 )
    print_label( pid, address )
