#!~/.wine/drive_c/Python25/python.exe

# Crash logger report, MS SQL version (see crash_logger.py)
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

__revision__ = "$Id$"

import os
import sys
import time

from winappdbg import CrashTableMSSQL
from crash_report import print_report_for_database

def connect_to_database(connection_string):
    print "Connecting to database..."
    cc = None
    try:
        cc = CrashTableMSSQL(connection_string)
    except Exception, e:
        print "Could not connect to database!"
        print "Error: %s" % str(e)
    return cc

def main(argv):
    print "Crash logger report (MS SQL)"
    print "by Mario Vilas (mvilas at gmail.com)"
    print
    if len(argv) == 1 or '--help' in argv:
        print "Usage:"
        print "    %s <ODBC connection string>" % os.path.basename(argv[0])
        print
        print "Produces a full report of each crash found by crash_logger.py"
    else:
        connection_string = ' '.join(argv[1:])
        cc = connect_to_database(connection_string)
        options = object()
        options.verbose = True
        print_report_for_database(cc, options)

if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
