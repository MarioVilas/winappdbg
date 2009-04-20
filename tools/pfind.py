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

#==============================================================================

class Search (object):
    
    name    = "query"
    desc    = "search query"
    errfmt  = "bad %(desc)s #%(count)d (%(pattern)r): %(text)s"
    showfmt = "Found element #%(count)d at process %(pid)d," \
              " address 0x%(address).08x (%(size)d bytes)"
    
    def __init__(self, pattern, count):
        self.pattern = pattern
        self.count   = count
        self.restart()
        self.initialize_pattern()

    def restart(self):
        self.start = -1
        self.end   = 0

    def shift(self, delta):
        self.start = self.start - delta
        self.end   = self.end   - delta
        if self.start < 0:
            self.start = -1
        if self.end < 0:
            self.end   = 0
    
    def update(self, start, end):
        if start < 0:
            if self.start >= 0:
                self.end = self.end + 1
            self.start = -1
        else:
            self.start = start
            self.end   = end
    
    def found(self):
        return self.start >= 0
    
    @classmethod
    def init_error_msg(cls, count, pattern, text):
        desc = cls.desc
        return cls.errfmt % vars()

    def message(self, pid, address, data = None):
        if self.start < 0:
            raise StopIteration
        count   = self.count + 1
        address = address + self.start
        size    = self.end - self.start
        msg     = self.showfmt % vars()
        if data is not None:
            msg += "\n"
            p = self.start & 0xFFFFFFF0
            q = (self.end & 0xFFFFFFF0) + 0x10
            msg += HexDump.hexblock( data[p:q] )
            if msg.endswith('\n'):
                msg = msg[:-len('\n')]
        return msg
    
    def initialize_pattern(self):
        raise NotImplementedError

    def search(self, data):
        raise NotImplementedError

#------------------------------------------------------------------------------

class StringSearch (Search):

    name    = "string"
    desc    = "case sensitive string"
    showfmt = "Found string #%(count)d at process %(pid)d," \
              " address 0x%(address).08x (%(size)d bytes)"
    
    def initialize_pattern(self):
        self.string = self.pattern
    
    def search(self, data):
        pos = data.find(self.string, self.end)
        self.update(pos, pos + len(self.pattern))

#------------------------------------------------------------------------------

class TextSearch (StringSearch):

    name    = "istring"
    desc    = "case insensitive string"
    showfmt = "Found text #%(count)d at process %(pid)d," \
              " address 0x%(address).08x (%(size)d bytes)"
    
    def initialize_pattern(self):
        self.string = self.pattern.lower()

    def search(self, data):
        super(TextSearch, self).search( data.lower() )

#------------------------------------------------------------------------------

class HexSearch (StringSearch):
    
    name    = "hexa"
    desc    = "hexadecimal data"
    showfmt = "Found data #%(count)d at process %(pid)d," \
              " address 0x%(address).08x (%(size)d bytes)"

    def initialize_pattern(self):
        self.string = HexInput.hexadecimal(self.pattern)

#------------------------------------------------------------------------------

class RegExpSearch (Search):

    name    = "regexp"
    desc    = "regular expression"
    showfmt = "Matched regexp #%(count)d at process %(pid)d," \
              " address 0x%(address).08x (%(size)d bytes)"
    
    def initialize_pattern(self):
        self.regexp = re.compile(self.pattern)
    
    def search(self, data):
        match = self.regexp.search(data, self.end)
        if match is None:
            self.update(-1, 0)
        else:
            self.update( * match.span() )

#------------------------------------------------------------------------------

class PatternSearch (RegExpSearch):
    name    = "pattern"
    desc    = "hexadecimal pattern"
    showfmt = "Found pattern #%(count)d at process %(pid)d," \
              " address 0x%(address).08x (%(size)d bytes)"
    
    def initialize_pattern(self):
        self.regexp = re.compile( HexInput.pattern(self.pattern) )

#==============================================================================

class Main (object):
    
    def __init__(self, argv):
        self.argv = argv
    
    def parse_cmdline(self):
        
        # An empty command line causes the help message to be shown
        if len(self.argv) == 1:
            self.argv = self.argv + ['-h']
        
        # Usage string
        usage  = "%prog [options] <target process IDs or names...>" 
        self.parser = optparse.OptionParser(usage=usage)
        
        # Options to set the search method
        search = optparse.OptionGroup(self.parser, "What to search",
                    "(at least one of these switches must be used)")
        search.add_option("-s", "--string", action="append", metavar="VALUE",
                          help="where VALUE is case sensitive text")
        search.add_option("-i", "--istring", action="append", metavar="VALUE",
                          help="where VALUE is case insensitive text")
        search.add_option("-x", "--hexa", action="append", metavar="VALUE",
                          help="where VALUE is hexadecimal data")
        search.add_option("-p", "--pattern", action="append", metavar="VALUE",
                          help="where VALUE is an hexadecimal pattern")
        search.add_option("-r", "--regexp", action="append", metavar="VALUE",
                          help="where VALUE is a POSIX regular expression")
        self.parser.add_option_group(search)
        
        # Options to control the search internals
        engine = optparse.OptionGroup(self.parser, "How to search")
##                    "Tweak the internals of the search mechanism.")
        engine.add_option("-m", "--memory-pages",
                          action="store", type="int", metavar="NUMBER",
                          help="maximum number of consecutive memory pages" \
                               " to read (matches larger than this won't"   \
                               " be found)         "   \
                               "[default: 2, use 0 for no limit]")
        self.parser.add_option_group(engine)
        
        # Options to set the output type
        output = optparse.OptionGroup(self.parser, "What to show")
##                    "Control the output.")
        output.add_option("-v", "--verbose", action="store_true", dest="verbose",
                          help="verbose output")
        output.add_option("-q", "--quiet", action="store_false", dest="verbose",
                          help="brief output [default]")
##        output.add_option("-c", "--color", action="store_true",
##                          help="Colorful output")
        self.parser.add_option_group(output)
        
        # Default values
        self.parser.set_defaults(
                   string = [],
                  istring = [],
                     hexa = [],
                  pattern = [],
                   regexp = [],
             memory_pages = 2,
                  verbose = False,
                    color = False,
            )
        
        # Parse the command line and check for validity
        (self.options, self.targets) = self.parser.parse_args(self.argv)
        
        # Our script's filename is not a target, skip it
        self.targets = self.targets[1:]
        
        # Fail if no search query was entered
        if not self.options.string  and \
           not self.options.istring and \
           not self.options.hexa    and \
           not self.options.pattern and \
           not self.options.regexp:
               self.parser.error("at least one search switch must be used")
    
    def prepare_input(self):
        
        # Build the lists of search objects
        self.build_searchers_list(StringSearch)
        self.build_searchers_list(TextSearch)
        self.build_searchers_list(HexSearch)
        self.build_searchers_list(PatternSearch)
        self.build_searchers_list(RegExpSearch)
        
        # Build the list of target pids
        self.build_targets_list()
    
    def build_searchers_list(self, cls):
        searchers = getattr(self.options, cls.name)
        for index in xrange(len(searchers)):
            try:
                searchers[index] = cls( searchers[index], index )
            except Exception, e:
                msg = cls.init_error_msg(index, searchers[index], e)
                self.parser.error(msg)
    
    def build_targets_list(self):
        
        # Take a process snapshot
        self.system = System()
        self.system.request_debug_privileges()
        self.system.scan_processes()
        
        # If no targets were given, search on all processes
        if not self.targets:
            self.targets = self.system.get_process_ids()
        
        # If targets were given, search only on those processes
        else:
            expanded_targets = set()
            for token in self.targets:
                try:
                    pid = HexInput.integer(token)
                    if not self.system.has_process(pid):
                        self.parser.error("process not found: %s" % token)
                    expanded_targets.add(pid)
                except ValueError:
                    found   = self.system.find_processes_by_filename(token)
                    pidlist = [process.get_pid() for (process, _) in found]
                    if not pidlist:
                        self.parser.error("process not found: %s" % token)
                    expanded_targets.update(pidlist)
            self.targets = list( expanded_targets )
        
        # Sort the targets list
        self.targets.sort()
    
    def do_search(self):
        
        # For each target process...
        for self.pid in self.targets:
            
            # Try to open the process, skip on error
            try:
                self.process = Process(self.pid)
                self.process.get_handle()
            except WindowsError:
                print "Can't open process %d, skipping" % self.pid
                if self.options.verbose:
                    print
                continue
            
            # Get a list of allocated memory regions
            memory = list()
            for mbi in self.process.get_memory_map():
                if mbi.State == win32.MEM_COMMIT and \
                                            not mbi.Protect & win32.PAGE_GUARD:
                    memory.append( (mbi.BaseAddress, mbi.RegionSize) )
            
            # If no allocation limit is set,
            # read entire regions and search on them
            if self.options.memory_pages <= 0:
                for (address, size) in memory:
                    data = self.process.read(address, size)
                    self.search_block(data, address, 0)
            
            # If an allocation limit is set,
            # read blocks within regions to search
            else:
                step = self.system.pageSize
                size = step * self.options.memory_pages
                for (address, total_size) in memory:
                    end    = address + total_size
                    shift  = 0
                    buffer = self.process.read(address, min(size, total_size))
                    while 1:
                        self.search_block(buffer, address, shift)
                        shift   = step
                        address = address + step
                        if address >= end:
                            break
                        buffer  = buffer[step:]
                        buffer  = buffer + self.process.read(address, step)
    
    def search_block(self, data, address, shift):
        self.search_block_with(self.options.string,  data, address, shift)
        self.search_block_with(self.options.istring, data, address, shift)
        self.search_block_with(self.options.hexa,    data, address, shift)
        self.search_block_with(self.options.pattern, data, address, shift)
        self.search_block_with(self.options.regexp,  data, address, shift)
    
    def search_block_with(self, searchers_list, data, address, shift):
        for searcher in searchers_list:
            if shift == 0:
                searcher.restart()
            else:
                searcher.shift(shift)
            while 1:
                searcher.search(data)
                if not searcher.found():
                    break
                if self.options.verbose:
                    print searcher.message(self.pid, address, data)
                    print
                else:
                    print searcher.message(self.pid, address)
    
    def run(self):
        
        # Banner
        print "Process memory finder"
        print "by Mario Vilas (mvilas at gmail.com)"
        print
        
        # Parse the command line
        self.parse_cmdline()
        
        # Prepare the input
        self.prepare_input()
        
        # Perform the search on the selected targets
        self.do_search()

#------------------------------------------------------------------------------

if __name__ == '__main__':
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    Main( sys.argv ).run()
