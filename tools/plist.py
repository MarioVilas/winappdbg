#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  http://tinyurl.com/nicolaseconomou

# Process enumerator
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

# TODO
# Show more info on processes, for example the user that spawned them, or if
# they're being debugged or not.

# TODO
# Show threads in each process (optionally).

# TODO
# Get the names of the services running in each process.

# TODO
# How about showing some colors?
# It'd be useful when using a search string, to highlight the matching parts.
# Also to show processes run by SYSTEM or other users with different colors.

from winappdbg import System, PathOperations, Table

import optparse

def parse_cmdline(argv):
    'Parse the command line options.'
    parser = optparse.OptionParser()
    parser.add_option("-f", "--full-path", action="store_true", default=False,
                      help="show full pathnames")
    parser.add_option("-s", "--search", metavar="STRING",
                      help="optional search string")
    (options, argv) = parser.parse_args(argv)
    if len(argv) > 1:
        parser.error("unexpected parameter: %s" % argv[1])
    return (options, argv)

def main(argv):
    'Main function.'

    # Print the banner.
    print "Process enumerator"
    print "by Mario Vilas (mvilas at gmail.com)"
    print

    # Parse the command line options.
    (options, argv)  = parse_cmdline(argv)
    showFilenameOnly = not options.full_path
    searchString     = options.search

    # Windows filenames are case insensitive.
    if searchString:
        searchString = searchString.lower()

    # Take a snapshot of the running processes.
    s = System()
    s.request_debug_privileges()
    s.scan_processes()
##    s.scan_processes_fast()
    pid_list = s.get_process_ids()
    pid_list.sort()

    # Prepare the output table.
    table = Table()
    table.addRow(" PID", "Filename")

    # Enumerate the processes in the snapshot.
    for pid in pid_list:
        p = s.get_process(pid)

        # Special process IDs.
        # PID 0: System Idle Process. Also has a special meaning to the
        #        toolhelp APIs (current process).
        # PID 4: System Integrity Group. See this forum post for more info:
        #        http://tinyurl.com/ycza8jo
        #        (points to social.technet.microsoft.com)
        #        Only on XP and above
        # PID 8: System (?) only in Windows 2000 and below AFAIK.
        #        It's probably the same as PID 4 in XP and above.
        if pid == 0:
            fileName = "[System Idle Process]"
        elif pid == 4:
            fileName = "[System]"
        elif pid == 8:
            fileName = "[System]"

        # Get the process filename (or pathname).
        else:
            fileName = p.get_filename()
            if not fileName:
##                fileName = "<unknown>"
                fileName = ""
            elif showFilenameOnly:
                fileName = PathOperations.pathname_to_filename(fileName)

        # Filter the output with the search string.
        if searchString and searchString not in fileName.lower():
            continue

        # Add the process PID and filename (or pathname).
        table.addRow(' %d' % pid, fileName)

    # Print the output table.
    table.justify(0, 1)
    for row in table.yieldOutput():
        print row

if __name__ == '__main__':
    import sys
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    main(sys.argv)
