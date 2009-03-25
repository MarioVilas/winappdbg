#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.

# Process killer
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

from winappdbg import win32, System, HexInput

import os
import sys
from thread import exit

def main(argv):
    script = os.path.basename(argv[0])
    params = argv[1:]

    print "Process killer"
    print "by Mario Vilas (mvilas at gmail.com)"
    print

    if len(params) == 0 or '-h' in params or '--help' in params or \
                                                     '/?' in params:
        print "Usage:"
        print "    %s <process ID or name> [process ID or name...]"
        print
        print "If a process name is given instead of an ID all matching processes are killed."
        exit()

    # Scan for active processes.
    # This is needed both to translate names to IDs, and to validate the user-supplied IDs.
    s = System()
    s.scan_processes()

    # Parse the command line.
    # Each ID is validated against the list of active processes.
    # Each name is translated to an ID.
    # On error, the program stops before killing any process at all.
    pid_set = set()
    for token in params:
        try:
            pid = HexInput.integer(token)
        except ValueError:
            pid = None
        if pid is None:
            matched = s.find_processes_by_filename(token)
            if not matched:
                print "Error: process not found: %s" % token
                exit()
            for (process, name) in matched:
                pid_set.add(process.get_pid())
        else:
            if not s.has_process(pid):
                print "Error: process not found: 0x%.8x (%d)" % (pid, pid)
                exit()
            pid_set.add(pid)

    # Attach to every process.
    # Print a message on errors, but don't stop.
    count = 0
    for pid in pid_set:
        try:
            win32.DebugActiveProcess(pid)
            count += 1
        except WindowsError, e:
            print "Warning: error attaching to %d: %s" % (pid, str(e))

    # Try to call the DebugSetProcessKillOnExit() API.
    #
    # Since it's defined only for Windows XP and above,
    # on earlier versions we just ignore the error,
    # since the default behavior on those platforms is
    # already what we wanted.
    #
    # This must be done after attaching to at least one process.
    #
    # http://msdn.microsoft.com/en-us/library/ms679307(VS.85).aspx
    try:
        win32.DebugSetProcessKillOnExit(True)
    except AttributeError:
        pass
    except WindowsError, e:
        print "Warning: call to DebugSetProcessKillOnExit() failed: %s" % str(e)

    if count == 0:
        print "Failed! No process was killed."
    elif count == 1:
        print "Successfully killed 1 process."
    else:
        print "Successfully killed %d processes." % count

    # Exit the current thread.
    # This will kill all the processes we have attached to.
    exit()

if __name__ == '__main__':
    main(sys.argv)
