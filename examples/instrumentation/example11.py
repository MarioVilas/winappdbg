# Copyright (c) 2009, Mario Vilas
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

# Example #11
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example11:resolveanAPIfunctioninaprocess

from winappdbg import Process, System

def print_api_address( pid, modName, procName ):

    # Request debug privileges
    System.request_debug_privileges()

    # Instance a Process object
    process = Process( pid )

    # Lookup it's modules
    process.scan_modules()

    # Get the module
    module = process.get_module_by_name( modName )
    if not module:
        print "Module not found: %s" % modName
        return

    # Resolve the requested API function address
    address = module.resolve( procName )

    # Print the address
    if address:
        print "%s!%s == 0x%.08x" % ( modName, procName, address )
    else:
        print "Could not resolve %s in module %s" % (procName, modName)

# When invoked from the command line,
# the first argument is a process ID,
# the second argunemt is a module name,
# the third argument is a procedure name
if __name__ == "__main__":
    import sys
    pid      = int( sys.argv[1] )
    modName  = sys.argv[2]
    procName = sys.argv[3]
    print_api_address( pid, modName, procName )
