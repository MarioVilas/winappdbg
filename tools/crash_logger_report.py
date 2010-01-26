#!~/.wine/drive_c/Python25/python.exe

# Crash logger report (see crash_logger.py)
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
import optparse

from winappdbg import CrashContainer, CrashTable

def parse_cmdline(argv):
    'Parse the command line options.'
    if len(argv) == 1:
        argv = argv + ['--help']
    usage  = (
             "\n    %prog <database file> [more database files...]\n"
             "\n"
             "Produces a full report of each crash found by crash_logger.py"
             )
    parser = optparse.OptionParser(usage=usage)
    parser.add_option("-v", "--verbose", action="store_true",  dest="verbose",
                                                help="produces a full report")
    parser.add_option("-q", "--quiet",   action="store_false", dest="verbose",
                                                help="produces a brief report")
    (options, argv) = parser.parse_args(argv)
    return (options, argv[1:])

def filter_duplicates(old_list):
    new_list = list()
    for filename in old_list:
        if filename not in new_list:
            new_list.append(filename)
        else:
            print "Skipping duplicate file: %s" % filename
    return new_list

def filter_inexistent_files(old_list):
    new_list = list()
    for filename in old_list:
        if os.path.exists(filename):
            new_list.append(filename)
        else:
            print "Cannot find file: %s" % filename
    return new_list

def open_database(filename):
    print "Opening database: %s" % filename
    cc = None

    # Try opening as a DBM database.
    try:
        import anydbm
        try:
            cc = CrashContainer( filename )
        except anydbm.error, e:
            error = str(e)
    except ImportError:
        print "Warning: no DBM support present"

    # Try opening as a SQLite database.
    if cc is None:
        try:
            try:
                import sqlite3 as sqlite
            except ImportError:
                from pysqlite2 import dbapi2 as sqlite
            try:
                cc = CrashTable( filename )
            except sqlite.DatabaseError, e:
                error = str(e)
        except ImportError:
            print "Warning: no SQLite support present"

    if cc is None:
        print "Error: %s: %r" % (error, filename)
    return cc

def print_report_for_database(filename, options):
    cc = open_database(filename)
    if cc:
        print "Found %d crashes:" % len(cc)
        print '-' * 79
        ccl = [(c.timeStamp, c) for c in cc]    # XXX may use a lot of memory
        ccl.sort()                  # XXX may fail if timestamps are repeated
        for (timeStamp, c) in ccl:
            local = time.localtime(timeStamp)
            ldate = time.strftime("%x", local)
            ltime = time.strftime("%X", local)
            msecs = (c.timeStamp % 1) * 1000
            msg = '%s %s.%04d' % (ldate, ltime, msecs)
            print msg
            if options.verbose:
                print c.fullReport()
            else:
                print c.briefReport()
            print '-' * 79
    elif cc is not None:
        print "No crashes to report."
        print

def main(argv):
    print "Crash logger report"
    print "by Mario Vilas (mvilas at gmail.com)"
    print

    (options, parameters) = parse_cmdline(argv)

    parameters = filter_duplicates(parameters)
    parameters = filter_inexistent_files(parameters)

    for filename in parameters:
        print_report_for_database(filename, options)

if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
