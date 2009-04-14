#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.

# Process memory finder
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

import re
import os
import sys
import optparse

from winappdbg import Process, System, HexDump, HexInput, win32

def parse_cmdline(argv):
    'Parse the command line options.'

    # An empty command line causes the help message to be shown
    if len(argv) == 1:
        argv = argv + ['-h']

    # Usage string
    usage  = "%prog [options] <QUERY> <target process IDs or names...>" 
    parser = optparse.OptionParser(usage=usage)

    # Options to set the search method
    search = optparse.OptionGroup(parser, "What to search")
##                "Specify how to understand the query string.")
    search.add_option("-s", "--string",
                      action="store_const", const="s", dest="search_method",
                      help="QUERY is a literal string (case sensitive)   [default]")
    search.add_option("-t", "--text",
                      action="store_const", const="t", dest="search_method",
                      help="QUERY is a literal string (case insensitive)")
    search.add_option("-x", "--hex",
                      action="store_const", const="x", dest="search_method",
                      help="QUERY is hexadecimal data")
##    search.add_option("-p", "--pattern",
##                      action="store_const", const="p", dest="search_method",
##                      help="QUERY is an hexadecimal pattern")
    search.add_option("-r", "--regexp",
                      action="store_const", const="r", dest="search_method",
                      help="QUERY is a POSIX regular expression")
    parser.add_option_group(search)

    # Options to control the search internals
    engine = optparse.OptionGroup(parser, "How to search")
##                "Tweak the internals of the search mechanism.")
    engine.add_option("-m", "--memory-pages",
                      action="store", type="int", metavar="NUMBER",
                      help="maximum number of consecutive memory pages"\
                           " to read [default: 2, use 0 for no limit]")
    parser.add_option_group(engine)

    # Options to set the output type
    output = optparse.OptionGroup(parser, "What to show")
##                "Control the output.")
    output.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      help="Verbose output")
    output.add_option("-q", "--quiet", action="store_false", dest="verbose",
                      help="Brief output [default]")
##    output.add_option("-c", "--color", action="store_true",
##                      help="Colorful output")
    parser.add_option_group(output)

    # Default values
    parser.set_defaults(
        search_method = "s",
         memory_pages = 2,
              verbose = False,
        )

    # Parse the command line and check for validity
    (options, argv) = parser.parse_args(argv)
    if len(argv) == 1:
        parser.error("missing query string")
    query   = argv[1]
    targets = argv[2:]

    # Convert hex dumps into strings
    if options.search_method == "x":
        options.search_method = "s"
        try:
            query = HexInput.binary(query)
        except ValueError:
            parser.error("invalid hexadecimal data")

##    # Convert hex patterns into regular expressions
##    elif options.search_method == "p":
##        options.search_method = "r"
##        
##        # TODO

    # Compile regular expressions
    elif options.search_method == "r":
        try:
            query = re.compile(query)
        except re.error, e:
            parser.error("bad regular expression %r: %s" % (query, e))

    # Return the options and arguments
    return (options, query, targets)

def main(argv):
    'Main function.'

    # Banner
    print "Process memory finder"
    print "by Mario Vilas (mvilas at gmail.com)"
    print

    # Parse the command line
    (options, query, targets) = parse_cmdline(argv)

    # Take a process snapshot
    system = System()
    system.scan_processes()

    # If no targets were given, search on all processes
    if not targets:
        expanded_targets = system.get_process_ids()

    # If targets were given, search only on those processes
    else:
        expanded_targets = list()
        for token in targets:
            try:
                pid = HexInput.integer(token)
                if not system.has_process(pid):
                    parser.error("process not found: %s" % token)
                expanded_targets.append(pid)
            except ValueError:
                plist = system.find_processes_by_filename(token)
                if not plist:
                    parser.error("process not found: %s" % token)
                for process, _ in plist:
                    expanded_targets.append(process.get_pid())

    # For each target process...
    for pid in expanded_targets:
        
        # Try to open the process, skip on error
        try:
            process = Process(pid)
            process.get_handle()
        except WindowsError:
            print "Can't open process %d, skipping" % pid
            continue
        
        # Get a list of allocated memory regions
        # If an allocation limit is set, break down the regions
        memory = list()
        for mbi in process.get_memory_map():
            if mbi.State == win32.MEM_COMMIT and \
                                            not mbi.Protect & win32.PAGE_GUARD:
                if options.memory_pages == 0:
                    memory.append( (mbi.BaseAddress, mbi.RegionSize) )
                else:
                    start = mbi.BaseAddress
                    end   = start + mbi.RegionSize
                    step  = system.pageSize * options.memory_pages
                    for address in xrange(start, end, step):
                        memory.append( (address, min(step, end - address)) )
        
        # Perform the search on each memory region
        if options.search_method == "t":
            query = query.lower()
        for (address, size) in memory:
##            if options.verbose:
##                print "Searching region at 0x%.08x (size 0x%.08x)" % \
##                                                                (address, size)
            
            # Read the memory
            data = process.read(address, size)
            if options.search_method == "t":
                data_lower = data.lower()
            
            # Find each occurence of the query
            p = -1
            q = 0
            while 1:
                
                # Case sensitive text search
                # (This includes hex data search, see parse_cmdline)
                if options.search_method == "s":
                    p = data.find(query, q)
                    if p >= 0:
                        q = p + len(query)
                    else:
                        q = 0
                
                # Case insensitive text search
                elif options.search_method == "t":
                    p = data_lower.find(query, q)
                    if p >= 0:
                        q = p + len(query)
                    else:
                        q = 0
                
    ##            # Hex pattern search
    ##            elif options.search_method == "p":
    ##                # TODO
                
                # Regular expression search
                elif options.search_method == "r":
                    m = query.search(data, q)
                    if m is not None:
                        p = m.start()
                        q = m.end()
                    else:
                        p = -1
                        q = 0
                
                # Quit the loop when the pattern can't be found anymore
                if p < 0:
                    break
                
                # Print the pattern found
                msg = ("Found at process %d address 0x%.08x,"
                       " %d bytes") % (pid, address + p, q - p)
                if options.verbose:
                    msg += "\n"
                    ap = p & 0xFFFFFFF0
                    aq = (q & 0xFFFFFFF0) + 0x10
                    msg += HexDump.hexblock(data[ap:aq])
                print msg

if __name__ == '__main__':
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    main( sys.argv )
