#!/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2020, Mario Vilas
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

from winappdbg import Process, System

def freeze_threads( pid ):

    # Request debug privileges.
    System.request_debug_privileges()

    # Instance a Process object.
    process = Process( pid )

    # This would also do the trick...
    #
    #   process.suspend()
    #
    # ...but let's do it the hard way:

    # Lookup the threads in the process.
    process.scan_threads()

    # For each thread in the process...
    for thread in process.iter_threads():

        # Suspend the thread execution.
        thread.suspend()

def unfreeze_threads( pid ):

    # Request debug privileges.
    System.request_debug_privileges()

    # Instance a Process object.
    process = Process( pid )

    # This would also do the trick...
    #
    #   process.resume()
    #
    # ...but let's do it the hard way:

    # Lookup the threads in the process.
    process.scan_threads()

    # For each thread in the process...
    for thread in process.iter_threads():

        # Resume the thread execution.
        thread.resume()

# When invoked from the command line,
# the first argument is either "f" or "u"
# the second argument is a process ID.
if __name__ == "__main__":
    import sys
    command = sys.argv[1][0].lower()
    pid = int( sys.argv[2] )
    if command == 'f':
        freeze_threads( pid )
    elif command == 'u':
        unfreeze_threads( pid )   # to reverse the effect
    else:
        script = sys.argv[0]
        print "%s f <pid> - freeze a process" % script
        print "%s u <pid> - unfreeze a process" % script
