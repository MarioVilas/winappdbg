#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.

# Process enumerator
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

from winappdbg import System

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

    # Prepare the format string for the output.
    w = len(str(pid_list[-1]))
    fmt = "%%%dd %%s" % w

##    # Print the output table header
##    print ("%%%ds Filename\n" % w) % "PID"

    # Enumerate the processes in the snapshot.
    for pid in pid_list:
        p = s.get_process(pid)

        # Special cases: PIDs 0 and 4.
        if pid == 0:
            fileName = "System process"
        elif pid == 4:
            fileName = "System"

        # Get the process filename (or pathname).
        else:
            try:
                fileName = p.get_filename()
                if showFilenameOnly:
##                    fileName = os.path.basename(fileName)
                    fileName = fileName[fileName.rfind('\\')+1:]
            except WindowsError:
##                raise   # XXX
                fileName = '<unknown>'

        # Filter the output with the search string.
        if searchString and searchString not in fileName.lower():
            continue

        # Print the process PID and filename (or pathname).
        print fmt % ( pid, fileName )

if __name__ == '__main__':
    import sys
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    main(sys.argv)
