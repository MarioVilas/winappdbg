#!/usr/bin/python3
# -*- coding: utf-8 -*-

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

"""
Process memory search.
"""

__all__ = [
    "Search",
    "Pattern",
    "StringPattern",
    "IStringPattern",
    "HexPattern",
    "AsciiStringsPattern",
    "UnicodeStringsPattern",
    "MemoryAccessWarning",
]

import warnings

from . import win32
from .textio import HexDump, HexInput
from .util import MemoryAddresses, StaticClass

try:
    # http://pypi.python.org/pypi/regex
    import regex as re
except ImportError:
    import re

# ==============================================================================


class MemoryAccessWarning(RuntimeWarning):
    """
    This warning is issued when a memory access error has occurred, but it can
    be safely ignored in most cases.
    """


# ==============================================================================


class Pattern:
    """
    Base class to code your own search mechanism.

    Normally you only need to reimplement the following methods:
     - ``__len__()``
     - ``next_match()``.
    """

    def __init__(self, pattern):
        """
        Class constructor.

        :type  pattern: bytes or str
        :param pattern: Pattern string.
            Its exact meaning and format depends on the subclass.
        """
        self.pattern = pattern
        self.start = None
        self.end = None
        self.data = None
        self.result = None
        self.pos = 0

    def reset(self):
        """
        Used internally to reset the internal state of the search engine.
        Subclasses don't normally need to reimplement this method.
        """
        self.start = None
        self.end = None
        self.data = None
        self.result = None
        self.pos = 0

    def shift(self, delta):
        """
        Used internally to adjust offsets when doing buffered searches.
        Subclasses don't normally need to reimplement this method.

        :type  delta: int
        :param delta: Delta offset.
        """
        self.start = None
        self.end = None
        self.data = None
        self.result = None
        self.pos = self.pos - delta
        if self.pos < 0:
            self.pos = 0

    def search(self, address, data, overlapping):
        """
        Searches for the pattern in the given data buffer.
        Subclasses don't normally need to reimplement this method.

        :type  address: int
        :param address: Memory address where the data was read from.
            Used to calculate the results tuple.

        :type  data: bytes
        :param data: Data buffer to search in.

        :type  overlapping: bool
        :param overlapping: ``True`` for overlapped searches,
            ``False`` otherwise.
        """
        self.data = data
        self.start = self.next_match()
        if self.start < 0:
            self.reset()
        else:
            self.end = self.start + len(self)
            self.result = (address + self.start, data[self.start : self.end])
            if overlapping:
                self.pos = self.start + 1
            else:
                self.pos = self.end

    def __len__(self):
        """
        :rtype:  int
        :return: maximum length of a string
            that can be matched by the pattern.
        """
        return len(self.pattern)

    def next_match(self):
        """
        This method **MUST** be reimplemented by subclasses.
        The data buffer can be found in ``self.data``.

        :rtype:  int
        :return: Position in the buffer where the pattern was found.
        """
        raise NotImplementedError()


# ------------------------------------------------------------------------------


class StringPattern(Pattern):
    """
    Pattern matching for static strings (case sensitive).
    """

    def __init__(self, pattern):
        """
        Class constructor.

        :type  pattern: bytes
        :param pattern: Static string to search for, case sensitive.
        """
        super().__init__(pattern)

    def next_match(self):
        return self.data.find(self.pattern, self.pos)


# ------------------------------------------------------------------------------


class IStringPattern(Pattern):
    """
    Pattern matching for static strings (case insensitive).
    """

    def __init__(self, pattern):
        """
        Class constructor.

        :type  pattern: bytes
        :param pattern: Static string to search for, case insensitive.
        """
        super().__init__(pattern.lower())

    def next_match(self):
        return self.data.lower().find(self.pattern, self.pos)


# ------------------------------------------------------------------------------


class HexPattern(Pattern):
    """
    Hexadecimal pattern matching with wildcards.

    Hex patterns must be in this form::

        "68 65 6c 6c 6f 20 77 6f 72 6c 64"  # "hello world"

    Spaces are optional. Capitalization of hex digits doesn't matter.
    This is exactly equivalent to the previous example::

        "68656C6C6F20776F726C64"            # "hello world"

    Wildcards are allowed, in the form of a ``?`` sign in any hex digit::

        "5? 5? c3"          # pop register / pop register / ret
        "b8 ?? ?? ?? ??"    # mov eax, immediate value
    """

    def __init__(self, pattern):
        """
        Class constructor.

        :type  pattern: str
        :param pattern:
            Hexadecimal pattern matching with wildcards.

            Hex patterns must be in this form::

                "68 65 6c 6c 6f 20 77 6f 72 6c 64"  # "hello world"

            Spaces are optional. Capitalization of hex digits doesn't matter.
            This is exactly equivalent to the previous example::

                "68656C6C6F20776F726C64"            # "hello world"

            Wildcards are allowed, in the form of a ``?`` sign in any hex digit::

                "5? 5? c3"          # pop register / pop register / ret
                "b8 ?? ?? ?? ??"    # mov eax, immediate value
        """
        super().__init__(pattern)
        if not HexInput.is_pattern(pattern):
            raise ValueError("Invalid hexadecimal pattern: %r" % pattern)
        self.length = HexInput.get_pattern_length(pattern)
        self.compiled = re.compile(HexInput.pattern(pattern), re.DOTALL)

    def __len__(self):
        return self.length

    def next_match(self):
        match = self.compiled.search(self.data[self.pos :])
        if match is not None:
            return match.start() + self.pos
        return -1


# ------------------------------------------------------------------------------


class AsciiStringsPattern(Pattern):
    """
    Pattern matching for extracting ASCII strings from binary data.

    This pattern extracts printable ASCII strings similar to the Unix
    ``strings`` command. Only characters in the range 0x20-0x7E (space to
    tilde) are considered printable.
    """

    def __init__(self, minLength=4):
        """
        Class constructor.

        :type  minLength: int
        :param minLength: Minimum length of strings to extract.
            Defaults to 4 characters.
        """
        # Pattern to match sequences of printable ASCII characters
        # Printable ASCII: space (0x20) to tilde (0x7E)
        pattern = rb"[\x20-\x7E]{%d,}" % minLength
        super().__init__(pattern)
        self.minLength = minLength
        self.compiled = re.compile(pattern)
        self.match = None

    def __len__(self):
        """
        Return the length of the last match.
        """
        if self.match is not None:
            return len(self.match.group(0))
        return self.minLength

    def next_match(self):
        """
        Find the next ASCII string in the data buffer.

        :rtype:  int
        :return: Position in the buffer where the string was found,
            or -1 if not found.
        """
        self.match = self.compiled.search(self.data, self.pos)
        if self.match is not None:
            return self.match.start()
        return -1


# ------------------------------------------------------------------------------


class UnicodeStringsPattern(Pattern):
    """
    Pattern matching for extracting Unicode (UTF-16LE) strings from binary data.

    This pattern extracts printable Unicode strings encoded as UTF-16LE
    (little-endian), which is the standard Unicode encoding on Windows.
    """

    def __init__(self, minLength=4):
        """
        Class constructor.

        :type  minLength: int
        :param minLength: Minimum length of strings to extract (in characters).
            Defaults to 4 characters.
        """
        # Pattern to match sequences of printable ASCII characters as UTF-16LE
        # Each character is represented as: char byte followed by null byte
        # Printable ASCII range: 0x20-0x7E
        pattern = rb"(?:[\x20-\x7E]\x00){%d,}" % minLength
        super().__init__(pattern)
        self.minLength = minLength * 2  # Each Unicode char is 2 bytes
        self.compiled = re.compile(pattern)
        self.match = None

    def __len__(self):
        """
        Return the length of the last match.
        """
        if self.match is not None:
            return len(self.match.group(0))
        return self.minLength

    def next_match(self):
        """
        Find the next Unicode string in the data buffer.

        :rtype:  int
        :return: Position in the buffer where the string was found,
            or -1 if not found.
        """
        self.match = self.compiled.search(self.data, self.pos)
        if self.match is not None:
            return self.match.start()
        return -1


# ==============================================================================


class Search(StaticClass):
    """
    Static class to group the search functionality.

    Do not instance this class! Use its static methods instead.
    """

    @classmethod
    def search_process(
        cls,
        process,
        patterns,
        minAddr=None,
        maxAddr=None,
        bufferPages=None,
        overlapping=True,
    ):
        """
        Search for the given string or pattern within the process memory.

        :type  process: :class:`~winappdbg.process.Process`
        :param process: Process to search.

        :type  patterns: list of :class:`~.Pattern`
        :param patterns: List of strings or wildcard patterns to search for.
            It must be an instance of a subclass of :class:`~.Pattern`.

            The following :class:`~.Pattern` subclasses are provided by WinAppDbg:
            - :class:`~.StringPattern` (case sensitive string search)
            - :class:`~.IStringPattern` (case insensitive string search)
            - :class:`~.HexPattern` (hexadecimal pattern with wildcards)

            You can also write your own subclass of :class:`~.Pattern`
            for customized searches.

        :type  minAddr: int
        :param minAddr: (Optional) Start the search at this memory address.

        :type  maxAddr: int
        :param maxAddr: (Optional) Stop the search at this memory address.

        :type  bufferPages: int
        :param bufferPages: (Optional) Number of memory pages to buffer when
            performing the search. Valid values are:

            - ``0`` or ``None``: Automatically determine the required buffer size.
              This is the default.
            - ``> 0``: Set the buffer size in memory pages.
            - ``< 0``: Disable buffering entirely. This may give you a little
              speed gain at the cost of an increased memory usage. If the
              target process has very large contiguous memory regions it may
              actually be slower or even fail.

        :type  overlapping: bool
        :param overlapping: ``True`` to allow overlapping results, ``False``
            otherwise.

            Overlapping results yield the maximum possible number of results.

            For example, if searching for "AAAA" within "AAAAAAAA" at address
            ``0x10000``, when overlapping is turned off the following matches
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

        :rtype:  iterator of tuple( int, int, bytes )
        :return: An iterator of tuples. Each tuple contains the following:
            - The memory address where the pattern was found.
            - The size of the data that matches the pattern.
            - The data that matches the pattern.

        :raises WindowsError: An error occurred when querying or reading the
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
            if mbi.State == win32.MEM_COMMIT and not mbi.Protect & win32.PAGE_GUARD:
                memory.append((mbi.BaseAddress, mbi.RegionSize))

        # If default buffer allocation is requested, calculate it.
        # We want one more page than the minimum required to allocate the
        # target string to find. Typically this will be 2 pages, since
        # most searches will not be looking for strings over 4k.
        # (We can't do it with 1 page - the target may be between pages!)
        if bufferPages is None or bufferPages == 0:
            bufferPages = MemoryAddresses.get_buffer_size_in_pages(
                0, sorted(map(len, patterns))[-1] + 1
            )

        # If no allocation limit is set,
        # read entire regions and search on them.
        if bufferPages <= 0:
            for address, size in memory:
                try:
                    data = process.read(address, size)
                except WindowsError as e:
                    begin = HexDump.address(address)
                    end = HexDump.address(address + size)
                    msg = "Error reading %s-%s: %s"
                    msg = msg % (begin, end, str(e))
                    warnings.warn(msg, MemoryAccessWarning)
                    continue
                for result in cls._search_block(
                    process, patterns, data, address, 0, overlapping
                ):
                    yield result

        # If an allocation limit is set,
        # read blocks within regions to search.
        else:
            step = MemoryAddresses.pageSize
            size = step * bufferPages
            for address, total_size in memory:
                try:
                    end = address + total_size
                    shift = 0
                    buffer = process.read(address, min(size, total_size))
                    while True:
                        for result in cls._search_block(
                            process, patterns, buffer, address, shift, overlapping
                        ):
                            yield result
                        shift = step
                        address = address + step
                        if address >= end:
                            break
                        buffer = buffer[step:]
                        buffer = buffer + process.read(address, step)
                except WindowsError as e:
                    begin = HexDump.address(address)
                    end = HexDump.address(address + total_size)
                    msg = "Error reading %s-%s: %s"
                    msg = msg % (begin, end, str(e))
                    warnings.warn(msg, MemoryAccessWarning)

    @staticmethod
    def _search_block(process, patterns, data, address, shift, overlapping):
        for searcher in patterns:
            if shift == 0:
                searcher.reset()
            else:
                searcher.shift(shift)
            while True:
                searcher.search(address, data, overlapping)
                if searcher.result is None:
                    break
                yield searcher.result
