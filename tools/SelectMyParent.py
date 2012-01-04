#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Didier Stevens, for his SelectMyParent tool on which this one is inspired.
#  http://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/

# SelectMyParent: Start a program with a selected parent process.
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

__revision__ = "$Id$"

import os
import sys

from winappdbg import win32, System, HexInput

def main(argv):

    # Print the banner.
    print "SelectMyParent: Start a program with a selected parent process"
    print "by Mario Vilas (mvilas at gmail.com)"
    print "based on a Didier Stevens tool (https://DidierStevens.com)"
    print

    # Check the command line arguments.
    if len(argv) < 3:
        script = os.path.basename(argv[0])
        print "  %s <pid> <process.exe> [arguments]" % script
        return

    # Request debug privileges.
    system = System()
    system.request_debug_privileges()

    # Parse the parent process argument.
    try:
        dwParentProcessId = HexInput.integer(argv[1])
    except ValueError:
        dwParentProcessId = None
    if dwParentProcessId is not None:
        dwMyProcessId = win32.GetProcessId( win32.GetCurrentProcess() )
        if dwParentProcessId != dwMyProcessId:
            system.scan_processes_fast()
            if not system.has_process(dwParentProcessId):
                print "Can't find process ID %d" % dwParentProcessId
                return
    else:
        system.scan_processes()
        process_list = system.find_processes_by_filename(argv[1])
        if not process_list:
            print "Can't find process %r" % argv[1]
            return
        if len(process_list) > 1:
            print "Too many processes found:"
            for process, name in process_list:
                print "\t%d:\t%s" % (process.get_pid(), name)
            return
        dwParentProcessId = process_list[0][0].get_pid()

    # Parse the target process argument.
    filename = argv[2]
    if not os.path.exists(filename):
        try:
            filename = win32.SearchPath(None, filename, '.exe')[0]
        except WindowsError, e:
            print "Error searching for %s: %s" % (filename, str(e))
            return
        argv = list(argv)
        argv[2] = filename

    # Start the new process.
    try:
        process = system.start_process(system.argv_to_cmdline(argv[2:]),
                                       bConsole          = True,
                                       bInheritHandles   = True,
                                       dwParentProcessId = dwParentProcessId)
        dwProcessId = process.get_pid()
    except AttributeError, e:
        if "InitializeProcThreadAttributeList" in str(e):
            print "This tool requires Windows Vista or above."
        else:
            print "Error starting new process: %s" % str(e)
        return
    except WindowsError, e:
        print "Error starting new process: %s" % str(e)
        return
    print "Process created: %d" % dwProcessId
    return dwProcessId

# Run main() binded to Psyco if available.
if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
