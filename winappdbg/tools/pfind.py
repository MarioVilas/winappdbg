#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  https://www.linkedin.com/in/nicolas-alejandro-economou-51468743/

# Process memory finder
# Copyright (c) 2009-2025, Mario Vilas
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

import optparse
import re
import sys

from winappdbg import win32
from winappdbg.process import Process
from winappdbg.system import System
from winappdbg.textio import HexDump, HexInput

# ==============================================================================


class Search:
    name = "query"
    desc = "search query"
    errfmt = "bad %(desc)s #%(count)d (%(pattern)r): %(text)s"
    showfmt = (
        "Found element #%(count)d at process %(pid)d,"
        " address %(where)s (%(size)d bytes)"
    )

    def __init__(self, pattern, count):
        self.pattern = pattern
        self.count = count
        self.restart()
        self.initialize_pattern()

    def restart(self):
        self.start = -1
        self.end = 0

    def shift(self, delta):
        self.start = self.start - delta
        self.end = self.end - delta
        if self.start < 0:
            self.start = -1
        if self.end < 0:
            self.end = 0

    def update(self, start, end):
        if start < 0:
            if self.start >= 0:
                self.end = self.end + 1
            self.start = -1
        else:
            self.start = start
            self.end = end

    def found(self):
        return self.start >= 0

    @classmethod
    def init_error_msg(cls, count, pattern, text):
        desc = cls.desc  # NOQA
        return cls.errfmt % vars()

    def message(self, pid, address, data=None):
        if self.start < 0:
            raise StopIteration
        count = self.count + 1  # NOQA
        address = address + self.start
        where = HexDump.address(address)  # NOQA
        size = self.end - self.start  # NOQA
        msg = self.showfmt % vars()
        if data is not None:
            msg += "\n"
            p = self.start & (~0xF)
            q = (self.end & (~0xF)) + 0x10
            msg += HexDump.hexblock(data[p:q], address & (~0xF))
            if msg.endswith("\n"):
                msg = msg[: -len("\n")]
        return msg

    def initialize_pattern(self):
        raise NotImplementedError

    def search(self, data):
        raise NotImplementedError


# ------------------------------------------------------------------------------


class StringSearch(Search):
    name = "string"
    desc = "case sensitive string"
    showfmt = (
        "Found string #%(count)d at process %(pid)d, address %(where)s (%(size)d bytes)"
    )

    def initialize_pattern(self):
        if isinstance(self.pattern, str):
            self.string = self.pattern.encode("latin-1")
        else:
            self.string = self.pattern

    def search(self, data):
        pos = data.find(self.string, self.end)
        if pos > -1:
            self.update(pos, pos + len(self.string))
        else:
            self.update(-1, 0)


# ------------------------------------------------------------------------------


class TextSearch(StringSearch):
    name = "istring"
    desc = "case insensitive string"
    showfmt = (
        "Found text #%(count)d at process %(pid)d, address %(where)s (%(size)d bytes)"
    )

    def initialize_pattern(self):
        if isinstance(self.pattern, str):
            self.string = self.pattern.lower().encode("latin-1")
        else:
            self.string = self.pattern.lower()

    def search(self, data):
        super().search(data.lower())


# ------------------------------------------------------------------------------


class HexSearch(StringSearch):
    name = "hexa"
    desc = "hexadecimal data"
    showfmt = (
        "Found data #%(count)d at process %(pid)d, address %(where)s (%(size)d bytes)"
    )

    def initialize_pattern(self):
        self.string = HexInput.hexadecimal(self.pattern)


# ------------------------------------------------------------------------------


class PatternSearch(Search):
    name = "pattern"
    desc = "hexadecimal pattern"
    showfmt = (
        "Found pattern #%(count)d at process %(pid)d,"
        " address %(where)s (%(size)d bytes)"
    )

    def initialize_pattern(self):
        self.regexp = re.compile(HexInput.pattern(self.pattern))

    def search(self, data):
        match = self.regexp.search(data, self.end)
        if match is None:
            self.update(-1, 0)
        else:
            self.update(*match.span())


# ==============================================================================


class Main:
    def __init__(self, argv):
        self.argv = argv

    def parse_cmdline(self):
        # An empty command line causes the help message to be shown
        if len(self.argv) == 1:
            self.argv = self.argv + ["-h"]

        # Usage string
        usage = "%prog [options] <target process IDs or names...>"
        self.parser = optparse.OptionParser(usage=usage)

        # Options to set the search method
        search = optparse.OptionGroup(
            self.parser,
            "What to search",
            "(at least one of these switches must be used)",
        )
        search.add_option(
            "-s",
            "--string",
            action="append",
            metavar="VALUE",
            help="where VALUE is case sensitive ANSI text",
        )
        search.add_option(
            "-i",
            "--istring",
            action="append",
            metavar="VALUE",
            help="where VALUE is case insensitive ANSI text",
        )
        search.add_option(
            "-S",
            "--ustring",
            action="append",
            metavar="VALUE",
            help="where VALUE is case sensitive Unicode text",
        )
        search.add_option(
            "-I",
            "--iustring",
            action="append",
            metavar="VALUE",
            help="where VALUE is case insensitive Unicode text",
        )
        search.add_option(
            "-x",
            "--hexa",
            action="append",
            metavar="VALUE",
            help="where VALUE is hexadecimal data",
        )
        search.add_option(
            "-p",
            "--pattern",
            action="append",
            metavar="VALUE",
            help="where VALUE is an hexadecimal pattern",
        )
        self.parser.add_option_group(search)

        # Options to control the search internals
        engine = optparse.OptionGroup(self.parser, "How to search")
        engine.add_option(
            "-m",
            "--memory-pages",
            action="store",
            type="int",
            metavar="NUMBER",
            help="maximum number of consecutive memory pages"
            " to read (matches larger than this won't"
            " be found)         "
            "[default: 2, use 0 for no limit]",
        )
        self.parser.add_option_group(engine)

        # Options to set the output type
        output = optparse.OptionGroup(self.parser, "What to show")
        output.add_option(
            "-v",
            "--verbose",
            action="store_true",
            dest="verbose",
            help="verbose output",
        )
        output.add_option(
            "-q",
            "--quiet",
            action="store_false",
            dest="verbose",
            help="brief output [default]",
        )
        self.parser.add_option_group(output)

        # Default values
        self.parser.set_defaults(
            string=[],
            istring=[],
            ustring=[],
            iustring=[],
            hexa=[],
            pattern=[],
            regexp=[],
            memory_pages=2,
            verbose=False,
        )

        # Parse the command line and check for validity
        (self.options, self.targets) = self.parser.parse_args(self.argv)

        # Our script's filename is not a target, skip it
        self.targets = self.targets[1:]

        # Fail if no search query was entered
        if (
            not self.options.string
            and not self.options.istring
            and not self.options.ustring
            and not self.options.iustring
            and not self.options.hexa
            and not self.options.pattern
        ):
            self.parser.error("at least one search switch must be used")

        # Convert the Unicode strings into ANSI strings internally.
        for s in self.options.ustring:
            try:
                s_bytes = s.encode("utf-16-le")
            except Exception:
                self.parser.error("Failed to encode Unicode string!")
            self.options.string.append(s_bytes)
        self.options.ustring = []
        for s in self.options.iustring:
            try:
                s_bytes = s.encode("utf-16-le")
            except Exception:
                self.parser.error("Failed to encode Unicode string!")
            self.options.istring.append(s_bytes)
        self.options.iustring = []

    def prepare_input(self):
        # Build the lists of search objects
        self.build_searchers_list(StringSearch)
        self.build_searchers_list(TextSearch)
        self.build_searchers_list(HexSearch)
        self.build_searchers_list(PatternSearch)

        # Build the list of target pids
        self.build_targets_list()

    def build_searchers_list(self, cls):
        searchers = getattr(self.options, cls.name)
        for index in range(len(searchers)):
            try:
                searchers[index] = cls(searchers[index], index)
            except Exception as e:
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
                    found = self.system.find_processes_by_filename(token)
                    pidlist = [process.get_pid() for (process, _) in found]
                    if not pidlist:
                        self.parser.error("process not found: %s" % token)
                    expanded_targets.update(pidlist)
            self.targets = list(expanded_targets)

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
                print("Can't open process %d, skipping" % self.pid)
                if self.options.verbose:
                    print()
                continue

            # Get a list of allocated memory regions
            memory = list()
            for mbi in self.process.get_memory_map():
                if mbi.State == win32.MEM_COMMIT and not mbi.Protect & win32.PAGE_GUARD:
                    memory.append((mbi.BaseAddress, mbi.RegionSize))

            # If no allocation limit is set,
            # read entire regions and search on them
            if self.options.memory_pages <= 0:
                for address, size in memory:
                    try:
                        data = self.process.read(address, size)
                    except WindowsError as e:
                        begin = HexDump.address(address)
                        end = HexDump.address(address + size)
                        msg = "Error reading %s-%s: %s"
                        msg = msg % (begin, end, str(e))
                        if self.options.verbose:
                            print(msg)
                        continue
                    self.search_block(data, address, 0)

            # If an allocation limit is set,
            # read blocks within regions to search
            else:
                step = self.system.pageSize
                size = step * self.options.memory_pages
                for address, total_size in memory:
                    try:
                        end = address + total_size
                        shift = 0
                        buffer = self.process.read(address, min(size, total_size))
                        while 1:
                            self.search_block(buffer, address, shift)
                            shift = step
                            address = address + step
                            if address >= end:
                                break
                            buffer = buffer[step:]
                            buffer = buffer + self.process.read(address, step)

                    except WindowsError as e:
                        begin = HexDump.address(address)
                        end = HexDump.address(address + total_size)
                        msg = "Error reading %s-%s: %s"
                        msg = msg % (begin, end, str(e))
                        if self.options.verbose:
                            print(msg)

    def search_block(self, data, address, shift):
        self.search_block_with(self.options.string, data, address, shift)
        self.search_block_with(self.options.istring, data, address, shift)
        self.search_block_with(self.options.hexa, data, address, shift)
        self.search_block_with(self.options.pattern, data, address, shift)

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
                    print(searcher.message(self.pid, address - shift, data))
                    print()
                else:
                    print(searcher.message(self.pid, address - shift))

    def run(self):
        # Banner
        print("Process memory finder")
        print("by Mario Vilas (mvilas at gmail.com)")
        print()

        # Parse the command line
        self.parse_cmdline()

        # Prepare the input
        self.prepare_input()

        # Perform the search on the selected targets
        self.do_search()

        return 0


# ------------------------------------------------------------------------------


def main():
    return Main(sys.argv).run()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
