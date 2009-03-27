#!~/.wine/drive_c/Python25/python.exe

# Crash dump report (see crash_dump.py)
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

import os
import sys
import time

from winappdbg import CrashContainer

def main():
    print "Crash dump report"
    print "by Mario Vilas (mvilas at gmail.com)"
    if len(sys.argv) != 2:
        print
        print "Produces a full report of each crash found by catch.py"
        print
        print "    %s <crash dump file>" % os.path.basename(sys.argv[0])
    else:
        print
        if not os.path.exists(sys.argv[1]):
            print "Cannot find file: %s" % sys.argv[1]
        else:
            cc = CrashContainer( sys.argv[1] )
            if cc:
                print "Found %d crashes:" % len(cc)
                print '-' * 79
                ccl = [(c.timeStamp, c) for c in cc]
                ccl.sort()
                for (timeStamp, c) in ccl:
##                    print "KEY", c.key()
##                    continue
                    local = time.localtime(timeStamp)
                    ldate = time.strftime("%x", local)
                    ltime = time.strftime("%X", local)
                    msecs = (c.timeStamp % 1) * 1000
                    msg = '%s %s.%04d' % (ldate, ltime, msecs)
                    print msg
##                    print c.briefReport()
                    print c.fullReport()
                    print '-' * 79
            else:
                print "No crashes to report."

if __name__ == '__main__':
    main()
