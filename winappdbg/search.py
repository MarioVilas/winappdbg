#!/bin/env python
# -*- coding: utf-8 -*-

# Process memory finder
# Copyright (c) 2009-2018, Mario Vilas
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

"""
Process memory search.

@group Memory search:
    Search,
    Pattern,
    StringPattern,
    IStringPattern,
    HexPattern
"""

__all__ =   [
                'Search',
                'Pattern',
                'StringPattern',
                'IStringPattern',
                'HexPattern',
            ]

from textio import HexInput
from util import StaticClass, MemoryAddresses
import win32

import warnings

try:
    # http://pypi.python.org/pypi/regex
    import regex as re
except ImportError:
    import re

#==============================================================================

class Pattern(object):
    """
    Base class to code your own search mechanism.

    Normally you only need to reimplement the following methods:
     - C{__len__}()
     - C{next_match}().
    """

    def __init__(self, pattern):
        """
        Class constructor.

        @type  pattern: str
        @param pattern: Pattern string.
            Its exact meaning and format depends on the subclass.
        """
        self.pattern = pattern
        self.start   = None
        self.end     = None
        self.data    = None
        self.result  = None
        self.pos     = 0

    def reset(self):
        """
        Used internally to reset the internal state of the search engine.
        Subclasses don't normally need to reimplement this method.
        """
        self.start   = None
        self.end     = None
        self.data    = None
        self.result  = None
        self.pos     = 0

    def shift(self, delta):
        """
        Used internally to adjust offsets when doing buffered searches.
        Subclasses don't normally need to reimplement this method.

        @type  delta: int
        @param delta: Delta offset.
        """
        self.start   = None
        self.end     = None
        self.data    = None
        self.result  = None
        self.pos     = self.pos - delta
        if self.pos < 0:
            self.pos = 0

    def search(self, address, data, overlapping):
        """
        Searches for the pattern in the given data buffer.
        Subclasses don't normally need to reimplement this method.

        @type  address: long
        @param address: Memory address where the data was read from.
            Used to calculate the results tuple.

        @type  data: str
        @param data: Data buffer to search in.

        @type  overlapping: bool
        @param overlapping: C{True} for overlapped searches,
            C{False} otherwise.
        """
        self.data = data
        self.start = self.next_match()
        if self.start < 0:
            self.reset()
        else:
            self.end = self.start + len(self)
            self.result = (address + self.start, data[ self.start : self.end ])
            if overlapping:
                self.pos = self.start + 1
            else:
                self.pos = self.end

    def __len__(self):
        """
        @rtype:  int
        @return: maximum length of a string
            that can be matched by the pattern.
        """
        return len(self.pattern)

    def next_match(self):
        """
        This method B{MUST} be reimplemented by subclasses.
        The data buffer can be found in C{self.data}.

        @rtype:  int
        @return: Position in the buffer where the pattern was found.
        """
        raise NotImplementedError()

#------------------------------------------------------------------------------

class StringPattern(Pattern):
    """
    Pattern matching for static strings (case sensitive).
    """

    def __init__(self, pattern):
        """
        Class constructor.

        @type  pattern: str
        @param pattern: Static string to search for, case sensitive.
        """
        super(StringPattern, self).__init__(pattern)

    def next_match(self):
        return self.data.find(self.pattern, self.pos)

#------------------------------------------------------------------------------

class IStringPattern(Pattern):
    """
    Pattern matching for static strings (case insensitive).
    """

    def __init__(self, pattern):
        """
        Class constructor.

        @type  pattern: str
        @param pattern: Static string to search for, case insensitive.
        """
        super(IStringPattern, self).__init__(pattern.lower())

    def next_match(self):
        return self.data.lower().find(self.pattern, self.pos)

#------------------------------------------------------------------------------

class HexPattern(Pattern):
    """
    Hexadecimal pattern matching with wildcards.

    Hex patterns must be in this form::
        "68 65 6c 6c 6f 20 77 6f 72 6c 64"  # "hello world"

    Spaces are optional. Capitalization of hex digits doesn't matter.
    This is exactly equivalent to the previous example::
        "68656C6C6F20776F726C64"            # "hello world"

    Wildcards are allowed, in the form of a C{?} sign in any hex digit::
        "5? 5? c3"          # pop register / pop register / ret
        "b8 ?? ?? ?? ??"    # mov eax, immediate value
    """

    def __init__(self, pattern):
        """
        Class constructor.

        @type  pattern: str
        @param pattern:
            Hexadecimal pattern matching with wildcards. 

            Hex patterns must be in this form::
                "68 65 6c 6c 6f 20 77 6f 72 6c 64"  # "hello world"

            Spaces are optional. Capitalization of hex digits doesn't matter.
            This is exactly equivalent to the previous example::
                "68656C6C6F20776F726C64"            # "hello world"

            Wildcards are allowed, in the form of a C{?} sign in any hex digit::
                "5? 5? c3"          # pop register / pop register / ret
                "b8 ?? ?? ?? ??"    # mov eax, immediate value
        """
        super(HexPattern, self).__init__(pattern)
        if not HexInput.is_pattern(pattern):
            raise ValueError("Invalid hexadecimal pattern: %r" % pattern)
        self.length   = HexInput.get_pattern_length(pattern)
        self.compiled = re.compile( HexInput.pattern(pattern), re.DOTALL )

    def __len__(self):
        return self.length

    def next_match(self):
        match = self.compiled.search( self.data[ self.pos : ] )
        if match is not None:
            return match.start() + self.pos
        return -1

#==============================================================================

class Search (StaticClass):
    """
    Static class to group the search functionality.

    Do not instance this class! Use its static methods instead.
    """

    @classmethod
    def search_process(cls, process, patterns, minAddr = None,
                                               maxAddr = None,
                                               bufferPages = None,
                                               overlapping = True):
        """
        Search for the given string or pattern within the process memory.

        @type  process: L{Process}
        @param process: Process to search.

        @type  patterns: L{list of Pattern}
        @param patterns: List of strings or wildcard patterns to search for.
            It must be an instance of a subclass of L{Pattern}.

            The following L{Pattern} subclasses are provided by WinAppDbg:
             - L{StringPattern} (case sensitive string search)
             - L{IStringPattern} (case insensitive string search)
             - L{HexPattern} (hexadecimal pattern with wildcards)

            You can also write your own subclass of L{Pattern}
            for customized searches.

        @type  minAddr: int
        @param minAddr: (Optional) Start the search at this memory address.

        @type  maxAddr: int
        @param maxAddr: (Optional) Stop the search at this memory address.

        @type  bufferPages: int
        @param bufferPages: (Optional) Number of memory pages to buffer when
            performing the search. Valid values are:
             - C{0} or C{None}: Automatically determine the required buffer size.
               This is the default.
             - C{> 0}: Set the buffer size in memory pages.
             - C{< 0}: Disable buffering entirely. This may give you a little
               speed gain at the cost of an increased memory usage. If the
               target process has very large contiguous memory regions it may
               actually be slower or even fail.

        @type  overlapping: bool
        @param overlapping: C{True} to allow overlapping results, C{False}
            otherwise.

            Overlapping results yield the maximum possible number of results.

            For example, if searching for "AAAA" within "AAAAAAAA" at address
            C{0x10000}, when overlapping is turned off the following matches
            are yielded::
                (0x10000, 4, "AAAA")
                (0x10004, 4, "AAAA")

            If overlapping is turned on, the following matches are yielded::
                (0x10000, 4, "AAAA")
                (0x10001, 4, "AAAA")
                (0x10002, 4, "AAAA")
                (0x10003, 4, "AAAA")
                (0x10004, 4, "AAAA")

            As you can see, the middle results are overlapping the last two.

        @rtype:  iterator of tuple( int, int, str )
        @return: An iterator of tuples. Each tuple contains the following:
             - The memory address where the pattern was found.
             - The size of the data that matches the pattern.
             - The data that matches the pattern.

        @raise WindowsError: An error occurred when querying or reading the
            process memory.
        """

        # Quit early if we have no list of patterns.
        if not patterns:
            return

        # Reset all patterns.
        for searcher in patterns:
            searcher.reset()

        # Get a list of allocated memory regions.
        memory = list()
        for mbi in process.get_memory_map(minAddr, maxAddr):
            if mbi.State == win32.MEM_COMMIT and \
                                        not mbi.Protect & win32.PAGE_GUARD:
                memory.append( (mbi.BaseAddress, mbi.RegionSize) )

        # If default buffer allocation is requested, calculate it.
        # We want one more page than the minimum required to allocate the
        # target string to find. Tipically this will be 2 pages, since
        # most searches will not be looking for strings over 4k.
        # (We can't do it with 1 page - the target may be between pages!)
        if bufferPages is None or bufferPages == 0:
            bufferPages = MemoryAddresses.get_buffer_size_in_pages(
                0, sorted(map(len, patterns))[-1] + 1)

        # If no allocation limit is set,
        # read entire regions and search on them.
        if bufferPages <= 0:
            for (address, size) in memory:
                try:
                    data = process.read(address, size)
                except WindowsError, e:
                    begin = HexDump.address(address)
                    end   = HexDump.address(address + size)
                    msg   = "Error reading %s-%s: %s"
                    msg   = msg % (begin, end, str(e))
                    warnings.warn(msg, RuntimeWarning)
                    continue
                for result in cls._search_block(
                            process, patterns, data, address, 0, overlapping):
                    yield result

        # If an allocation limit is set,
        # read blocks within regions to search.
        else:
            step = MemoryAddresses.pageSize
            size = step * bufferPages
            for (address, total_size) in memory:
                try:
                    end    = address + total_size
                    shift  = 0
                    buffer = process.read(address, min(size, total_size))
                    while 1:
                        for result in cls._search_block(
                                    process, patterns, buffer,
                                    address, shift, overlapping):
                            yield result
                        shift   = step
                        address = address + step
                        if address >= end:
                            break
                        buffer  = buffer[step:]
                        buffer  = buffer + process.read(address, step)
                except WindowsError, e:
                    begin = HexDump.address(address)
                    end   = HexDump.address(address + total_size)
                    msg   = "Error reading %s-%s: %s"
                    msg   = msg % (begin, end, str(e))
                    warnings.warn(msg, RuntimeWarning)

    @staticmethod
    def _search_block(process, patterns, data, address, shift, overlapping):
        for searcher in patterns:
            if shift == 0:
                searcher.reset()
            else:
                searcher.shift(shift)
            while 1:
                searcher.search(address, data, overlapping)
                if searcher.result is None:
                    break
                yield searcher.result
