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

def main(argv):
    print "Process enumerator"
    print "by Mario Vilas (mvilas at gmail.com)"
    print
    if '-h' in argv or '/?' in argv:
        import os
        script = os.path.basename(argv[0])
        print "  %s [options]"
        print
        print "Options:"
        print "    -f         Show full pathnames"
        print "    -h         Show this help message"
        return
    showFilenameOnly = '-f' not in argv

    s = System()
    s.request_debug_privileges()
    s.scan_processes()
##    s.scan_processes_fast()
    pid_list = s.get_process_ids()
    pid_list.sort()

    w = len(str(pid_list[-1]))
##    print ("%%%ds Filename\n" % w) % "PID"
    fmt = "%%%dd %%s" % w
    for pid in pid_list:
        p = s.get_process(pid)
        if pid == 0:
            fileName = "System process"
        elif pid == 4:
            fileName = "System"
        else:
            try:
                fileName = p.get_filename()
                if showFilenameOnly:
##                    fileName = os.path.basename(fileName)
                    fileName = fileName[fileName.rfind('\\')+1:]
            except WindowsError:
##                raise   # XXX
                fileName = p.unknown
        print fmt % ( pid, fileName )

if __name__ == '__main__':
    import sys
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    main(sys.argv)
