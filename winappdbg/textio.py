#!/usr/bin/python3
# -*- coding: utf-8 -*-

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
Functions for text input, logging or text output.
"""

__all__ = [
    "HexDump",
    "HexInput",
    "HexOutput",
    "Color",
    "Table",
    "CrashDump",
    "DebugLog",
    "Logger",
]

import os
import re
import struct
import time
import traceback

from . import win32
from .util import StaticClass

# ------------------------------------------------------------------------------


class HexInput(StaticClass):
    """
    Static functions for user input parsing.
    The counterparts for each method are in the :class:`HexOutput` class.
    """

    @staticmethod
    def integer(token):
        """
        Convert numeric strings into integers.

        :param token: String to parse.
        :type  token: str

        :return: Parsed integer value.
        :rtype:  int
        """
        token = token.strip()
        neg = False
        if token.startswith("-"):
            token = token[1:]
            neg = True
        if token.startswith("0x"):
            result = int(token, 16)  # hexadecimal
        elif token.startswith("0b"):
            result = int(token, 0)  # binary
        elif token.startswith("0o"):
            result = int(token, 0)  # octal
        else:
            try:
                result = int(token)  # decimal
            except ValueError:
                result = int(token, 16)  # hexadecimal (no "0x" prefix)
        if neg:
            result = -result
        return result

    @staticmethod
    def address(token):
        """
        Convert numeric strings into memory addresses.

        :param token: String to parse.
        :type  token: str

        :return: Parsed integer value.
        :rtype:  int
        """
        return int(token, 16)

    @staticmethod
    def hexadecimal(token):
        """
        Convert a strip of hexadecimal numbers into binary data.

        :param token: String to parse.
        :type  token: str

        :return: Parsed string value.
        :rtype:  bytes
        """
        token = "".join([c for c in token if c.isalnum()])
        if len(token) % 2 != 0:
            raise ValueError("Missing characters in hex data")
        data = bytearray()
        for i in range(0, len(token), 2):
            x = token[i : i + 2]
            d = int(x, 16)
            s = struct.pack("<B", d)
            data.extend(s)
        return bytes(data)

    @staticmethod
    def pattern(token):
        """
        Convert an hexadecimal search pattern into a POSIX regular expression.

        For example, the following pattern::

            "B8 0? ?0 ?? ??"

        Would match the following data::

            "B8 0D F0 AD BA"    # mov eax, 0xBAADF00D

        :param token: String to parse.
        :type  token: str

        :return: Parsed string value.
        :rtype:  bytes
        """
        token = "".join([c for c in token if c == "?" or c.isalnum()])
        if len(token) % 2 != 0:
            raise ValueError("Missing characters in hex data")
        regexp = b""
        for i in range(0, len(token), 2):
            x = token[i : i + 2]
            if x == "??":
                regexp += b"."
            elif x[0] == "?":
                f = b"\\x%%.1x%s" % x[1].encode("ascii")
                x = b"".join([f % c for c in range(0, 0x10)])
                regexp = b"%s[%s]" % (regexp, x)
            elif x[1] == "?":
                f = b"\\x%s%%.1x" % x[0].encode("ascii")
                x = b"".join([f % c for c in range(0, 0x10)])
                regexp = b"%s[%s]" % (regexp, x)
            else:
                regexp = b"%s\\x%s" % (regexp, x.encode("ascii"))
        return regexp

    @staticmethod
    def is_pattern(token):
        """
        Determine if the given argument is a valid hexadecimal pattern to be
        used with :meth:`pattern`.

        :param token: String to parse.
        :type  token: str

        :return: ``True`` if it's a valid hexadecimal pattern, ``False`` otherwise.
        :rtype:  bool
        """
        return re.match(r"^(?:[\?A-Fa-f0-9][\?A-Fa-f0-9]\s*)+$", token) is not None

    @staticmethod
    def get_pattern_length(token):
        """
        Determine the byte length of the given hexadecimal pattern to be
        used with :meth:`pattern`.

        :param token: String to parse.
        :type  token: str

        :return: Length in bytes.
        :rtype:  int
        """
        token = "".join([c for c in token if c == "?" or c.isalnum()])
        if len(token) % 2 != 0:
            raise ValueError("Missing characters in hex data")
        return len(token) // 2

    @classmethod
    def integer_list_file(cls, filename):
        """
        Read a list of integers from a file.

        The file format is:

         - # anywhere in the line begins a comment
         - leading and trailing spaces are ignored
         - empty lines are ignored
         - integers can be specified as:
            - decimal numbers ("100" is 100)
            - hexadecimal numbers ("0x100" is 256)
            - binary numbers ("0b100" is 4)
            - octal numbers ("0100" is 64)

        :param filename: Name of the file to read.
        :type  filename: str

        :return: List of integers read from the file.
        :rtype:  list[int]
        """
        count = 0
        result = list()
        with open(filename, "r", encoding="utf-8") as fd:
            for line in fd:
                count = count + 1
                if "#" in line:
                    line = line[: line.find("#")]
                line = line.strip()
                if line:
                    try:
                        value = cls.integer(line)
                    except ValueError as e:
                        msg = "Error in line %d of %s: %s"
                        msg = msg % (count, filename, str(e))
                        raise ValueError(msg)
                    result.append(value)
        return result

    @classmethod
    def string_list_file(cls, filename):
        """
        Read a list of string values from a file.

        The file format is:

         - # anywhere in the line begins a comment
         - leading and trailing spaces are ignored
         - empty lines are ignored
         - strings cannot span over a single line

        :param filename: Name of the file to read.
        :type  filename: str

        :return: List of integers and strings read from the file.
        :rtype:  list[str]
        """
        count = 0
        result = list()
        with open(filename, "r", encoding="utf-8") as fd:
            for line in fd:
                count = count + 1
                if "#" in line:
                    line = line[: line.find("#")]
                line = line.strip()
                if line:
                    result.append(line)
        return result

    @classmethod
    def mixed_list_file(cls, filename):
        """
        Read a list of mixed values from a file.

        The file format is:

         - # anywhere in the line begins a comment
         - leading and trailing spaces are ignored
         - empty lines are ignored
         - strings cannot span over a single line
         - integers can be specified as:
            - decimal numbers ("100" is 100)
            - hexadecimal numbers ("0x100" is 256)
            - binary numbers ("0b100" is 4)
            - octal numbers ("0100" is 64)

        :param filename: Name of the file to read.
        :type  filename: str

        :return: List of integers and strings read from the file.
        :rtype:  list
        """
        count = 0
        result = list()
        with open(filename, "r", encoding="utf-8") as fd:
            for line in fd:
                count = count + 1
                if "#" in line:
                    line = line[: line.find("#")]
                line = line.strip()
                if line:
                    try:
                        value = cls.integer(line)
                    except ValueError:
                        value = line
                    result.append(value)
        return result


# ------------------------------------------------------------------------------


class HexOutput(StaticClass):
    """
    Static functions for user output parsing.
    The counterparts for each method are in the :class:`HexInput` class.

    :cvar int integer_size: Default size in characters of an outputted integer.
        This value is platform dependent.

    :cvar int address_size: Default Number of bits of the target architecture.
        This value is platform dependent.
    """

    integer_size = (win32.SIZEOF(win32.DWORD) * 2) + 2
    address_size = (win32.SIZEOF(win32.SIZE_T) * 2) + 2

    @classmethod
    def integer(cls, integer, bits=None):
        """
        :param integer: Integer.
        :type  integer: int

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`integer_size`
        :type  bits: int

        :return: Text output.
        :rtype:  str
        """
        if bits is None:
            integer_size = cls.integer_size
        else:
            integer_size = (bits // 4) + 2
        if integer >= 0:
            return ("0x%%.%dx" % (integer_size - 2)) % integer
        return ("-0x%%.%dx" % (integer_size - 2)) % -integer

    @classmethod
    def address(cls, address, bits=None):
        """
        :param address: Memory address.
        :type  address: int

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :return: Text output.
        :rtype:  str
        """
        if bits is None:
            address_size = cls.address_size
            bits = win32.bits
        else:
            address_size = (bits // 4) + 2
        if address < 0:
            address = ((2**bits) - 1) ^ ~address
        return ("0x%%.%dx" % (address_size - 2)) % address

    @staticmethod
    def hexadecimal(data):
        """
        Convert binary data to a string of hexadecimal numbers.

        :param data: Binary data.
        :type  data: str

        :return: Hexadecimal representation.
        :rtype:  str
        """
        return HexDump.hexadecimal(data, separator="")

    @classmethod
    def integer_list_file(cls, filename, values, bits=None):
        """
        Write a list of integers to a file.
        If a file of the same name exists, it's contents are replaced.

        See :meth:`~winappdbg.textio.HexInput.integer_list_file`
        for a description of the file format.

        :param filename: Name of the file to write.
        :type  filename: str

        :param values: List of integers to write to the file.
        :type  values: list[int]

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`integer_size`
        :type  bits: int
        """
        with open(filename, "w", encoding="utf-8") as fd:
            for integer in values:
                fd.write(cls.integer(integer, bits) + os.linesep)

    @classmethod
    def string_list_file(cls, filename, values):
        """
        Write a list of strings to a file.
        If a file of the same name exists, it's contents are replaced.

        See :meth:`~winappdbg.textio.HexInput.string_list_file`
        for a description of the file format.

        :param filename: Name of the file to write.
        :type  filename: str

        :param values: List of strings to write to the file.
        :type  values: list[str]
        """
        with open(filename, "w", encoding="utf-8") as fd:
            fd.writelines([s + os.linesep for s in values])

    @classmethod
    def mixed_list_file(cls, filename, values, bits):
        """
        Write a list of mixed values to a file.
        If a file of the same name exists, it's contents are replaced.

        See :meth:`~winappdbg.textio.HexInput.mixed_list_file`
        for a description of the file format.

        :param filename: Name of the file to write.
        :type  filename: str

        :param values: List of mixed values to write to the file.
        :type  values: list

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`integer_size`
        :type  bits: int
        """
        with open(filename, "w", encoding="utf-8") as fd:
            for original in values:
                try:
                    parsed = cls.integer(original, bits)
                except TypeError:
                    parsed = repr(original)
                fd.write(parsed + os.linesep)


# ------------------------------------------------------------------------------


class HexDump(StaticClass):
    """
    Static functions for hexadecimal dumps.

    :cvar int integer_size: Size in characters of an outputted integer.
        This value is platform dependent.

    :cvar int address_size: Size in characters of an outputted address.
        This value is platform dependent.
    """

    integer_size = win32.SIZEOF(win32.DWORD) * 2
    address_size = win32.SIZEOF(win32.SIZE_T) * 2

    @classmethod
    def integer(cls, integer, bits=None):
        """
        :param integer: Integer.
        :type  integer: int

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`integer_size`
        :type  bits: int

        :return: Text output.
        :rtype:  str
        """
        if bits is None:
            integer_size = cls.integer_size
        else:
            integer_size = bits // 4
        return ("%%.%dX" % integer_size) % (integer,)

    @classmethod
    def address(cls, address, bits=None):
        """
        :param address: Memory address.
        :type  address: int

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :return: Text output.
        :rtype:  str
        """
        if bits is None:
            address_size = cls.address_size
            bits = win32.bits
        else:
            address_size = bits // 4
        if address < 0:
            address = ((2**bits) - 1) ^ ~address
        return ("%%.%dX" % address_size) % (address,)

    @staticmethod
    def printable(data):
        """
        Replace unprintable characters with dots.

        :param data: Binary data.
        :type  data: str

        :return: Printable text.
        :rtype:  str
        """
        result = ""
        if isinstance(data, str):
            data = data.encode("latin-1", "replace")
        for c in data:
            if 32 < c < 128:
                result += chr(c)
            else:
                result += "."
        return result

    @staticmethod
    def hexadecimal(data, separator=""):
        """
        Convert binary data to a string of hexadecimal numbers.

        :param data: Binary data.
        :type  data: str

        :param separator: Separator between the hexadecimal
            representation of each character.
        :type  separator: str

        :return: Hexadecimal representation.
        :rtype:  str
        """
        return separator.join(["%.2x" % c for c in data])

    @staticmethod
    def hexa_word(data, separator=" "):
        """
        Convert binary data to a string of hexadecimal WORDs.

        :param data: Binary data.
        :type  data: str

        :param separator: Separator between the hexadecimal
            representation of each WORD.
        :type  separator: str

        :return: Hexadecimal representation.
        :rtype:  str
        """
        if len(data) & 1 != 0:
            data += b"\0"
        return separator.join(
            [
                "%.4x" % struct.unpack("<H", data[i : i + 2])[0]
                for i in range(0, len(data), 2)
            ]
        )

    @staticmethod
    def hexa_dword(data, separator=" "):
        """
        Convert binary data to a string of hexadecimal DWORDs.

        :param data: Binary data.
        :type  data: str

        :param separator: Separator between the hexadecimal
            representation of each DWORD.
        :type  separator: str

        :return: Hexadecimal representation.
        :rtype:  str
        """
        if len(data) & 3 != 0:
            data += b"\0" * (4 - (len(data) & 3))
        return separator.join(
            [
                "%.8x" % struct.unpack("<L", data[i : i + 4])[0]
                for i in range(0, len(data), 4)
            ]
        )

    @staticmethod
    def hexa_qword(data, separator=" "):
        """
        Convert binary data to a string of hexadecimal QWORDs.

        :param data: Binary data.
        :type  data: str

        :param separator: Separator between the hexadecimal
            representation of each QWORD.
        :type  separator: str

        :return: Hexadecimal representation.
        :rtype:  str
        """
        if len(data) & 7 != 0:
            data += b"\0" * (8 - (len(data) & 7))
        return separator.join(
            [
                "%.16x" % struct.unpack("<Q", data[i : i + 8])[0]
                for i in range(0, len(data), 8)
            ]
        )

    @classmethod
    def hexline(cls, data, separator=" ", width=None):
        """
        Dump a line of hexadecimal numbers from binary data.

        :param data: Binary data.
        :type  data: str

        :param separator: Separator between the hexadecimal
            representation of each character.
        :type  separator: str

        :param width: (Optional) Maximum number of characters to convert per
            text line. This value is also used for padding.
        :type  width: int

        :return: Multiline output text.
        :rtype:  str
        """
        if width is None:
            fmt = "%s  %s"
        else:
            fmt = "%%-%ds  %%-%ds" % ((len(separator) + 2) * width - 1, width)
        return fmt % (cls.hexadecimal(data, separator), cls.printable(data))

    @classmethod
    def hexblock(cls, data, address=None, bits=None, separator=" ", width=8):
        """
        Dump a block of hexadecimal numbers from binary data.
        Also show a printable text version of the data.

        :param data: Binary data.
        :type  data: str

        :param address: Memory address where the data was read from.
        :type  address: str

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :param separator: Separator between the hexadecimal
            representation of each character.
        :type  separator: str

        :param width: (Optional) Maximum number of characters to convert
            per text line.
        :type  width: int

        :return: Multiline output text.
        :rtype:  str
        """
        return cls.hexblock_cb(
            cls.hexline,
            data,
            address,
            bits,
            width,
            cb_kwargs={"width": width, "separator": separator},
        )

    @classmethod
    def hexblock_cb(
        cls, callback, data, address=None, bits=None, width=16, cb_args=(), cb_kwargs={}
    ):
        """
        Dump a block of binary data using a callback function to convert each
        line of text.

        :param callback: Callback function to convert each line of data.
        :type  callback: function

        :param data: Binary data.
        :type  data: str

        :param address: (Optional) Memory address where the data was read from.
        :type  address: str

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :param cb_args: (Optional) Arguments to pass to the callback function.
        :type  cb_args: str

        :param cb_kwargs: (Optional) Keyword arguments to pass to the
            callback function.
        :type  cb_kwargs: str

        :param width: (Optional) Maximum number of bytes to convert
            per text line.
        :type  width: int

        :return: Multiline output text.
        :rtype:  str
        """
        result = ""
        if address is None:
            for i in range(0, len(data), width):
                result = "%s%s\n" % (
                    result,
                    callback(data[i : i + width], *cb_args, **cb_kwargs),
                )
        else:
            for i in range(0, len(data), width):
                result = "%s%s: %s\n" % (
                    result,
                    cls.address(address, bits),
                    callback(data[i : i + width], *cb_args, **cb_kwargs),
                )
                address += width
        return result

    @classmethod
    def hexblock_byte(cls, data, address=None, bits=None, separator=" ", width=16):
        """
        Dump a block of hexadecimal BYTEs from binary data.

        :param data: Binary data.
        :type  data: str

        :param address: Memory address where the data was read from.
        :type  address: str

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :param separator: Separator between the hexadecimal
            representation of each BYTE.
        :type  separator: str

        :param width: (Optional) Maximum number of BYTEs to convert
            per text line.
        :type  width: int

        :return: Multiline output text.
        :rtype:  str
        """
        return cls.hexblock_cb(
            cls.hexadecimal,
            data,
            address,
            bits,
            width,
            cb_kwargs={"separator": separator},
        )

    @classmethod
    def hexblock_word(cls, data, address=None, bits=None, separator=" ", width=8):
        """
        Dump a block of hexadecimal WORDs from binary data.

        :param data: Binary data.
        :type  data: str

        :param address: Memory address where the data was read from.
        :type  address: str

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :param separator: Separator between the hexadecimal
            representation of each WORD.
        :type  separator: str

        :param width: (Optional) Maximum number of WORDs to convert
            per text line.
        :type  width: int

        :return: Multiline output text.
        :rtype:  str
        """
        return cls.hexblock_cb(
            cls.hexa_word,
            data,
            address,
            bits,
            width * 2,
            cb_kwargs={"separator": separator},
        )

    @classmethod
    def hexblock_dword(cls, data, address=None, bits=None, separator=" ", width=4):
        """
        Dump a block of hexadecimal DWORDs from binary data.

        :param data: Binary data.
        :type  data: str

        :param address: Memory address where the data was read from.
        :type  address: str

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :param separator: Separator between the hexadecimal
            representation of each DWORD.
        :type  separator: str

        :param width: (Optional) Maximum number of DWORDs to convert
            per text line.
        :type  width: int

        :return: Multiline output text.
        :rtype:  str
        """
        return cls.hexblock_cb(
            cls.hexa_dword,
            data,
            address,
            bits,
            width * 4,
            cb_kwargs={"separator": separator},
        )

    @classmethod
    def hexblock_qword(cls, data, address=None, bits=None, separator=" ", width=2):
        """
        Dump a block of hexadecimal QWORDs from binary data.

        :param data: Binary data.
        :type  data: str

        :param address: Memory address where the data was read from.
        :type  address: str

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`address_size`
        :type  bits: int

        :param separator: Separator between the hexadecimal
            representation of each QWORD.
        :type  separator: str

        :param width: (Optional) Maximum number of QWORDs to convert
            per text line.
        :type  width: int

        :return: Multiline output text.
        :rtype:  str
        """
        return cls.hexblock_cb(
            cls.hexa_qword,
            data,
            address,
            bits,
            width * 8,
            cb_kwargs={"separator": separator},
        )


# ------------------------------------------------------------------------------

# TODO: implement an ANSI parser to simplify using colors


class Color:
    """
    Colored console output.
    """

    @staticmethod
    def _get_text_attributes():
        return win32.GetConsoleScreenBufferInfo().wAttributes

    @staticmethod
    def _set_text_attributes(wAttributes):
        win32.SetConsoleTextAttribute(wAttributes=wAttributes)

    # --------------------------------------------------------------------------

    @classmethod
    def can_use_colors(cls):
        """
        Determine if we can use colors.

        Colored output only works when the output is a real console, and fails
        when redirected to a file or pipe. Call this method before issuing a
        call to any other method of this class to make sure it's actually
        possible to use colors.

        :return: ``True`` if it's possible to output text with color,
            ``False`` otherwise.
        :rtype:  bool
        """
        try:
            cls._get_text_attributes()
            return True
        except Exception:
            return False

    @classmethod
    def reset(cls):
        "Reset the colors to the default values."
        cls._set_text_attributes(win32.FOREGROUND_GREY)

    # --------------------------------------------------------------------------

    # @classmethod
    # def underscore(cls, on = True):
    #    wAttributes = cls._get_text_attributes()
    #    if on:
    #        wAttributes |=  win32.COMMON_LVB_UNDERSCORE
    #    else:
    #        wAttributes &= ~win32.COMMON_LVB_UNDERSCORE
    #    cls._set_text_attributes(wAttributes)

    # --------------------------------------------------------------------------

    @classmethod
    def default(cls):
        "Make the current foreground color the default."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_GREY
        wAttributes &= ~win32.FOREGROUND_INTENSITY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def light(cls):
        "Make the current foreground color light."
        wAttributes = cls._get_text_attributes()
        wAttributes |= win32.FOREGROUND_INTENSITY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def dark(cls):
        "Make the current foreground color dark."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_INTENSITY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def black(cls):
        "Make the text foreground color black."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        # wAttributes |=  win32.FOREGROUND_BLACK
        cls._set_text_attributes(wAttributes)

    @classmethod
    def white(cls):
        "Make the text foreground color white."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_GREY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def red(cls):
        "Make the text foreground color red."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_RED
        cls._set_text_attributes(wAttributes)

    @classmethod
    def green(cls):
        "Make the text foreground color green."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_GREEN
        cls._set_text_attributes(wAttributes)

    @classmethod
    def blue(cls):
        "Make the text foreground color blue."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_BLUE
        cls._set_text_attributes(wAttributes)

    @classmethod
    def cyan(cls):
        "Make the text foreground color cyan."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_CYAN
        cls._set_text_attributes(wAttributes)

    @classmethod
    def magenta(cls):
        "Make the text foreground color magenta."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_MAGENTA
        cls._set_text_attributes(wAttributes)

    @classmethod
    def yellow(cls):
        "Make the text foreground color yellow."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.FOREGROUND_MASK
        wAttributes |= win32.FOREGROUND_YELLOW
        cls._set_text_attributes(wAttributes)

    # --------------------------------------------------------------------------

    @classmethod
    def bk_default(cls):
        "Make the current background color the default."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        # wAttributes |= win32.BACKGROUND_BLACK
        wAttributes &= ~win32.BACKGROUND_INTENSITY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_light(cls):
        "Make the current background color light."
        wAttributes = cls._get_text_attributes()
        wAttributes |= win32.BACKGROUND_INTENSITY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_dark(cls):
        "Make the current background color dark."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_INTENSITY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_black(cls):
        "Make the text background color black."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        # wAttributes |= win32.BACKGROUND_BLACK
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_white(cls):
        "Make the text background color white."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        wAttributes |= win32.BACKGROUND_GREY
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_red(cls):
        "Make the text background color red."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        wAttributes |= win32.BACKGROUND_RED
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_green(cls):
        "Make the text background color green."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        wAttributes |= win32.BACKGROUND_GREEN
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_blue(cls):
        "Make the text background color blue."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        wAttributes |= win32.BACKGROUND_BLUE
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_cyan(cls):
        "Make the text background color cyan."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        wAttributes |= win32.BACKGROUND_CYAN
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_magenta(cls):
        "Make the text background color magenta."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        wAttributes |= win32.BACKGROUND_MAGENTA
        cls._set_text_attributes(wAttributes)

    @classmethod
    def bk_yellow(cls):
        "Make the text background color yellow."
        wAttributes = cls._get_text_attributes()
        wAttributes &= ~win32.BACKGROUND_MASK
        wAttributes |= win32.BACKGROUND_YELLOW
        cls._set_text_attributes(wAttributes)


# ------------------------------------------------------------------------------

# TODO: another class for ASCII boxes


class Table:
    """
    Text based table. The number of columns and the width of each column
    is automatically calculated.
    """

    def __init__(self, sep=" "):
        """
        :param sep: Separator between cells in each row.
        :type  sep: str
        """
        self.__cols = list()
        self.__width = list()
        self.__sep = sep

    def addRow(self, *row):
        """
        Add a row to the table. All items are converted to strings.

        :param row: Each argument is a cell in the table.
        :type  row: tuple
        """
        row = [str(item) for item in row]
        len_row = [len(item) for item in row]
        width = self.__width
        len_old = len(width)
        len_new = len(row)
        # known   = min(len_old, len_new)
        missing = len_new - len_old
        if missing > 0:
            width.extend(len_row[-missing:])
        elif missing < 0:
            len_row.extend([0] * (-missing))
        self.__width = [max(width[i], len_row[i]) for i in range(len(len_row))]
        self.__cols.append(row)

    def justify(self, column, direction):
        """
        Make the text in a column left or right justified.

        :param column: Index of the column.
        :type  column: int

        :param direction: ``-1`` to justify left, ``1`` to justify right.
        :type  direction: int

        :raises IndexError: Bad column index.
        :raises ValueError: Bad direction value.
        """
        if direction == -1:
            self.__width[column] = abs(self.__width[column])
        elif direction == 1:
            self.__width[column] = -abs(self.__width[column])
        else:
            raise ValueError("Bad direction value.")

    def getWidth(self):
        """
        Get the width of the text output for the table.

        :return: Width in characters for the text output,
            including the newline character.
        :rtype:  int
        """
        width = 0
        if self.__width:
            width = sum(abs(x) for x in self.__width)
            width = width + len(self.__width) * len(self.__sep) + 1
        return width

    def getOutput(self):
        """
        Get the text output for the table.

        :return: Text output.
        :rtype:  str
        """
        return "%s\n" % "\n".join(self.yieldOutput())

    def yieldOutput(self):
        """
        Generate the text output for the table.

        :return: Text output.
        :rtype:  generator of str
        """
        width = self.__width
        if width:
            num_cols = len(width)
            fmt = ["%%%ds" % -w for w in width]
            if width[-1] > 0:
                fmt[-1] = "%s"
            fmt = self.__sep.join(fmt)
            for row in self.__cols:
                row.extend([""] * (num_cols - len(row)))
                yield fmt % tuple(row)

    def show(self):
        """
        print(the text output for the table.)
        """
        print(self.getOutput())


# ------------------------------------------------------------------------------


class CrashDump(StaticClass):
    """
    Static functions for crash dumps.

    :cvar str reg_template: Template for the :meth:`dump_registers` method.
    """

    # Templates for the dump_registers method.
    reg_template = {
        win32.ARCH_I386: (
            "eax=%(Eax).8x ebx=%(Ebx).8x ecx=%(Ecx).8x edx=%(Edx).8x esi=%(Esi).8x edi=%(Edi).8x\n"
            "eip=%(Eip).8x esp=%(Esp).8x ebp=%(Ebp).8x %(efl_dump)s\n"
            "cs=%(SegCs).4x  ss=%(SegSs).4x  ds=%(SegDs).4x  es=%(SegEs).4x  fs=%(SegFs).4x  gs=%(SegGs).4x             efl=%(EFlags).8x\n"
        ),
        win32.ARCH_AMD64: (
            "rax=%(Rax).16x rbx=%(Rbx).16x rcx=%(Rcx).16x\n"
            "rdx=%(Rdx).16x rsi=%(Rsi).16x rdi=%(Rdi).16x\n"
            "rip=%(Rip).16x rsp=%(Rsp).16x rbp=%(Rbp).16x\n"
            " r8=%(R8).16x  r9=%(R9).16x r10=%(R10).16x\n"
            "r11=%(R11).16x r12=%(R12).16x r13=%(R13).16x\n"
            "r14=%(R14).16x r15=%(R15).16x\n"
            "%(efl_dump)s\n"
            "cs=%(SegCs).4x  ss=%(SegSs).4x  ds=%(SegDs).4x  es=%(SegEs).4x  fs=%(SegFs).4x  gs=%(SegGs).4x             efl=%(EFlags).8x\n"
        ),
        win32.ARCH_ARM64: (
            " x0=%(X0).16x  x1=%(X1).16x   x2=%(X2).16x\n"
            " x3=%(X3).16x  x4=%(X4).16x   x5=%(X5).16x\n"
            " x6=%(X6).16x  x7=%(X7).16x   x8=%(X8).16x\n"
            " x9=%(X9).16x  x10=%(X10).16x x11=%(X11).16x\n"
            "x12=%(X12).16x  x13=%(X13).16x x14=%(X14).16x\n"
            "x15=%(X15).16x  x16=%(X16).16x x17=%(X17).16x\n"
            "x18=%(X18).16x  x19=%(X19).16x x20=%(X20).16x\n"
            "x21=%(X21).16x  x22=%(X22).16x x23=%(X23).16x\n"
            "x24=%(X24).16x  x25=%(X25).16x x26=%(X26).16x\n"
            "x27=%(X27).16x  x28=%(X28).16x\n"
            " fp=%(Fp).16x   lr=%(Lr).16x\n"
            " pc=%(Pc).16x   sp=%(Sp).16x\n"
            " cpsr=%(Cpsr).8x         %(cpsr_dump)s\n"
        ),
    }

    @staticmethod
    def dump_x86_flags(efl):
        """
        Dump the x86 processor flags.
        The output mimics that of the WinDBG debugger.
        Used by :meth:`dump_registers`.

        :param efl: Value of the eFlags register.
        :type  efl: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if efl is None:
            return ""
        efl_dump = "iopl=%1d" % ((efl & 0x3000) >> 12)
        if efl & 0x100000:
            efl_dump += " vip"
        else:
            efl_dump += "    "
        if efl & 0x80000:
            efl_dump += " vif"
        else:
            efl_dump += "    "
        # 0x20000 ???
        if efl & 0x800:
            efl_dump += " ov"  # Overflow
        else:
            efl_dump += " no"  # No overflow
        if efl & 0x400:
            efl_dump += " dn"  # Downwards
        else:
            efl_dump += " up"  # Upwards
        if efl & 0x200:
            efl_dump += " ei"  # Enable interrupts
        else:
            efl_dump += " di"  # Disable interrupts
        # 0x100 trap flag
        if efl & 0x80:
            efl_dump += " ng"  # Negative
        else:
            efl_dump += " pl"  # Positive
        if efl & 0x40:
            efl_dump += " zr"  # Zero
        else:
            efl_dump += " nz"  # Nonzero
        if efl & 0x10:
            efl_dump += " ac"  # Auxiliary carry
        else:
            efl_dump += " na"  # No auxiliary carry
        # 0x8 ???
        if efl & 0x4:
            efl_dump += " pe"  # Parity odd
        else:
            efl_dump += " po"  # Parity even
        # 0x2 ???
        if efl & 0x1:
            efl_dump += " cy"  # Carry
        else:
            efl_dump += " nc"  # No carry
        return efl_dump

    @staticmethod
    def dump_arm_flags(cpsr):
        """
        Dump the ARM64 processor status register flags.
        The output format is similar to the x86 flags dump.
        Used by :meth:`dump_registers`.

        :param cpsr: Value of the CPSR register.
        :type  cpsr: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if cpsr is None:
            return ""

        # Extract flag bits
        flag_dump = ""

        # Condition flags (NZCV)
        if cpsr & 0x80000000:  # N flag (bit 31)
            flag_dump += " ng"  # Negative
        else:
            flag_dump += " pl"  # Positive

        if cpsr & 0x40000000:  # Z flag (bit 30)
            flag_dump += " zr"  # Zero
        else:
            flag_dump += " nz"  # Non-zero

        if cpsr & 0x20000000:  # C flag (bit 29)
            flag_dump += " cy"  # Carry
        else:
            flag_dump += " nc"  # No carry

        if cpsr & 0x10000000:  # V flag (bit 28)
            flag_dump += " ov"  # Overflow
        else:
            flag_dump += " nv"  # No overflow

        # Exception level and stack pointer selection
        el = (cpsr >> 2) & 0x3  # EL[1:0] bits 3:2
        sp_sel = cpsr & 0x1     # SPSel bit 0
        flag_dump += f" el{el}"
        if sp_sel:
            flag_dump += " spx"  # Use SPx
        else:
            flag_dump += " sp0"  # Use SP0

        # Interrupt masks
        if cpsr & 0x200:  # D flag (bit 9) - Debug exception mask
            flag_dump += " dbg"
        if cpsr & 0x100:  # A flag (bit 8) - SError interrupt mask
            flag_dump += " serr"
        if cpsr & 0x80:   # I flag (bit 7) - IRQ interrupt mask
            flag_dump += " irq"
        if cpsr & 0x40:   # F flag (bit 6) - FIQ interrupt mask
            flag_dump += " fiq"

        return flag_dump.strip()

    @classmethod
    def dump_registers(cls, registers, arch=None):
        """
        Dump the x86/x64 processor register values.
        The output mimics that of the WinDBG debugger.

        :param registers: Dictionary mapping register names to their values.
        :type  registers: dict[str, int]

        :param arch: Architecture of the machine whose registers were dumped.
            Defaults to the current architecture.

            Currently only the following architectures are supported:

             - :const:`winappdbg.win32.ARCH_I386`
             - :const:`winappdbg.win32.ARCH_AMD64`
             - :const:`winappdbg.win32.ARCH_ARM64`
        :type  arch: str

        :return: Text suitable for logging.
        :rtype:  str
        """
        if registers is None:
            return ""
        registers = registers.copy()

        if arch is None:
            if "Eax" in registers:
                arch = win32.ARCH_I386
                registers["efl_dump"] = cls.dump_x86_flags(registers["EFlags"])
            elif "Rax" in registers:
                arch = win32.ARCH_AMD64
                registers["efl_dump"] = cls.dump_x86_flags(registers["EFlags"])
            elif "X0" in registers:
                arch = win32.ARCH_ARM64
                registers["cpsr_dump"] = cls.dump_arm_flags(registers["Cpsr"])
            else:
                arch = "Unknown"
        if arch not in cls.reg_template:
            msg = "Don't know how to dump the registers for architecture: %s"
            raise NotImplementedError(msg % arch)

        # Handle missing segment registers in x86/x64 architectures.
        # Use sentinel value 0xFFFF to indicate unavailable registers.
        # This will happen when running in x86-on-ARM emulation.
        if arch in (win32.ARCH_I386, win32.ARCH_AMD64):
            sentinel_value = 0xFFFF  # Clearly invalid segment value
            segment_registers = ['SegCs', 'SegSs', 'SegDs', 'SegEs', 'SegFs', 'SegGs']
            for seg in segment_registers:
                if seg not in registers:
                    registers[seg] = sentinel_value

        return cls.reg_template[arch] % registers

    @staticmethod
    def dump_registers_peek(registers, data, separator=" ", width=16):
        """
        Dump data pointed to by the given registers, if any.

        :param registers: Dictionary mapping register names to their values.
            This value is returned by :meth:`~winappdbg.thread.Thread.get_context`.
        :type  registers: dict[str, int]

        :param data: Dictionary mapping register names to the data they point to.
            This value is returned by
            :meth:`~winappdbg.thread.Thread.peek_pointers_in_registers`.
        :type  data: dict[str, str]

        :return: Text suitable for logging.
        :rtype:  str
        """
        if None in (registers, data):
            return ""
        names = sorted(data)
        result = ""
        for reg_name in names:
            tag = reg_name.lower()
            dumped = HexDump.hexline(data[reg_name], separator, width)
            result += "%s -> %s\n" % (tag, dumped)
        return result

    @staticmethod
    def dump_data_peek(data, base=0, separator=" ", width=16, bits=None):
        """
        Dump data from pointers guessed within the given binary data.

        :param data: Dictionary mapping offsets to the data they point to.
        :type  data: str

        :param base: Base offset.
        :type  base: int

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`~HexDump.address_size`
        :type  bits: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if data is None:
            return ""
        pointers = sorted(data)
        result = ""
        for offset in pointers:
            dumped = HexDump.hexline(data[offset], separator, width)
            address = HexDump.address(base + offset, bits)
            result += "%s -> %s\n" % (address, dumped)
        return result

    @staticmethod
    def dump_stack_peek(data, separator=" ", width=16, arch=None):
        """
        Dump data from pointers guessed within the given stack dump.

        :param data: Dictionary mapping stack offsets to the data they point to.
        :type  data: str

        :param separator: Separator between the hexadecimal
            representation of each character.
        :type  separator: str

        :param width: (Optional) Maximum number of characters to convert per
            text line. This value is also used for padding.
        :type  width: int

        :param arch: Architecture of the machine whose registers were dumped.
            Defaults to the current architecture.
        :type  arch: str

        :return: Text suitable for logging.
        :rtype:  str
        """
        if data is None:
            return ""
        if arch is None:
            arch = win32.arch
        pointers = sorted(data)
        result = ""
        if pointers:
            if arch == win32.ARCH_I386:
                spreg = "esp"
            elif arch == win32.ARCH_AMD64:
                spreg = "rsp"
            else:
                spreg = "STACK"  # just a generic tag
            tag_fmt = "[%s+0x%%.%dx]" % (spreg, len("%x" % pointers[-1]))
            for offset in pointers:
                dumped = HexDump.hexline(data[offset], separator, width)
                tag = tag_fmt % offset
                result += "%s -> %s\n" % (tag, dumped)
        return result

    @staticmethod
    def dump_stack_trace(stack_trace, bits=None):
        """
        Dump a stack trace, as returned by
        :meth:`~winappdbg.thread.Thread.get_stack_trace`
        with the ``bUseLabels`` parameter set to ``False``.

        :param stack_trace: Stack trace as a list of tuples of
            ( return address, frame pointer, module filename )
        :type  stack_trace: list[tuple(int, int, str)]

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`~HexDump.address_size`
        :type  bits: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if not stack_trace:
            return ""
        table = Table()
        table.addRow("Frame", "Origin", "Module")
        for fp, ra, mod in stack_trace:
            fp_d = HexDump.address(fp, bits)
            ra_d = HexDump.address(ra, bits)
            table.addRow(fp_d, ra_d, mod)
        return table.getOutput()

    @staticmethod
    def dump_stack_trace_with_labels(stack_trace, bits=None):
        """
        Dump a stack trace,
        as returned by :meth:`~winappdbg.thread.Thread.get_stack_trace_with_labels`.

        :param stack_trace: Stack trace as a list of tuples of
            ( return address, frame pointer, module filename )
        :type  stack_trace: list[tuple(int, str)]

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`~HexDump.address_size`
        :type  bits: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if not stack_trace:
            return ""
        table = Table()
        table.addRow("Frame", "Origin")
        for fp, label in stack_trace:
            table.addRow(HexDump.address(fp, bits), label)
        return table.getOutput()

    # TODO
    # + Instead of a star when EIP points to, it would be better to show
    # any register value (or other values like the exception address) that
    # points to a location in the dissassembled code.
    # + It'd be very useful to show some labels here.
    # + It'd be very useful to show register contents for code at EIP
    @staticmethod
    def dump_code(disassembly, pc=None, bLowercase=True, bits=None):
        """
        Dump a disassembly. Optionally mark where the program counter is.

        :param disassembly: Disassembly dump as returned by
            :meth:`~winappdbg.process.Process.disassemble` or
            :meth:`~winappdbg.thread.Thread.disassemble_around_pc`.
        :type  disassembly: list[tuple(int, int, str, str)]

        :param pc: (Optional) Program counter.
        :type  pc: int

        :param bLowercase: (Optional) If ``True`` convert the code to lowercase.
        :type  bLowercase: bool

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`~HexDump.address_size`
        :type  bits: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if not disassembly:
            return ""
        table = Table(sep=" | ")
        for addr, size, code, dump in disassembly:
            if bLowercase:
                code = code.lower()
            if addr == pc:
                addr = " * %s" % HexDump.address(addr, bits)
            else:
                addr = "   %s" % HexDump.address(addr, bits)
            table.addRow(addr, dump, code)
        table.justify(1, 1)
        return table.getOutput()

    @staticmethod
    def dump_code_line(
        disassembly_line,
        bShowAddress=True,
        bShowDump=True,
        bLowercase=True,
        dwDumpWidth=None,
        dwCodeWidth=None,
        bits=None,
    ):
        """
        Dump a single line of code. To dump a block of code use :meth:`dump_code`.

        :param disassembly_line: Single item of the list returned by
            :meth:`~winappdbg.process.Process.disassemble` or
            :meth:`~winappdbg.thread.Thread.disassemble_around_pc`.
        :type  disassembly_line: tuple(int, int, str, str)

        :param bShowAddress: (Optional) If ``True`` show the memory address.
        :type  bShowAddress: bool

        :param bShowDump: (Optional) If ``True`` show the hexadecimal dump.
        :type  bShowDump: bool

        :param bLowercase: (Optional) If ``True`` convert the code to lowercase.
        :type  bLowercase: bool

        :param dwDumpWidth: (Optional) Width in characters of the hex dump.
        :type  dwDumpWidth: int or None

        :param dwCodeWidth: (Optional) Width in characters of the code.
        :type  dwCodeWidth: int or None

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`~HexDump.address_size`
        :type  bits: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if bits is None:
            address_size = HexDump.address_size
        else:
            address_size = bits // 4
        (addr, size, code, dump) = disassembly_line
        dump = dump.replace(" ", "")
        result = list()
        fmt = ""
        if bShowAddress:
            result.append(HexDump.address(addr, bits))
            fmt += "%%%ds:" % address_size
        if bShowDump:
            result.append(dump)
            if dwDumpWidth:
                fmt += " %%-%ds" % dwDumpWidth
            else:
                fmt += " %s"
        if bLowercase:
            code = code.lower()
        result.append(code)
        if dwCodeWidth:
            fmt += " %%-%ds" % dwCodeWidth
        else:
            fmt += " %s"
        return fmt % tuple(result)

    @staticmethod
    def dump_memory_map(memoryMap, mappedFilenames=None, bits=None):
        """
        Dump the memory map of a process. Optionally show the filenames for
        memory mapped files as well.

        :param memoryMap: Memory map returned by
            :meth:`~winappdbg.process.Process.get_memory_map`.
        :type  memoryMap: list[win32.MemoryBasicInformation]

        :param mappedFilenames: (Optional) Memory mapped filenames
            returned by :meth:`~winappdbg.process.Process.get_mapped_filenames`.
        :type  mappedFilenames: dict[int, str]

        :param bits: (Optional) Number of bits of the target architecture.
            The default is platform dependent. See: :attr:`~HexDump.address_size`
        :type  bits: int

        :return: Text suitable for logging.
        :rtype:  str
        """
        if not memoryMap:
            return ""

        table = Table()
        if mappedFilenames:
            table.addRow("Address", "Size", "State", "Access", "Type", "File")
        else:
            table.addRow("Address", "Size", "State", "Access", "Type")

        # For each memory block in the map...
        for mbi in memoryMap:
            # Address and size of memory block.
            BaseAddress = HexDump.address(mbi.BaseAddress, bits)
            RegionSize = HexDump.address(mbi.RegionSize, bits)

            # State (free or allocated).
            mbiState = mbi.State
            if mbiState == win32.MEM_RESERVE:
                State = "Reserved"
            elif mbiState == win32.MEM_COMMIT:
                State = "Commited"
            elif mbiState == win32.MEM_FREE:
                State = "Free"
            else:
                State = "Unknown"

            # Page protection bits (R/W/X/G).
            if mbiState != win32.MEM_COMMIT:
                Protect = ""
            else:
                mbiProtect = mbi.Protect
                if mbiProtect & win32.PAGE_NOACCESS:
                    Protect = "--- "
                elif mbiProtect & win32.PAGE_READONLY:
                    Protect = "R-- "
                elif mbiProtect & win32.PAGE_READWRITE:
                    Protect = "RW- "
                elif mbiProtect & win32.PAGE_WRITECOPY:
                    Protect = "RC- "
                elif mbiProtect & win32.PAGE_EXECUTE:
                    Protect = "--X "
                elif mbiProtect & win32.PAGE_EXECUTE_READ:
                    Protect = "R-X "
                elif mbiProtect & win32.PAGE_EXECUTE_READWRITE:
                    Protect = "RWX "
                elif mbiProtect & win32.PAGE_EXECUTE_WRITECOPY:
                    Protect = "RCX "
                else:
                    Protect = "??? "
                if mbiProtect & win32.PAGE_GUARD:
                    Protect += "G"
                else:
                    Protect += "-"
                if mbiProtect & win32.PAGE_NOCACHE:
                    Protect += "N"
                else:
                    Protect += "-"
                if mbiProtect & win32.PAGE_WRITECOMBINE:
                    Protect += "W"
                else:
                    Protect += "-"

            # Type (file mapping, executable image, or private memory).
            mbiType = mbi.Type
            if mbiType == win32.MEM_IMAGE:
                Type = "Image"
            elif mbiType == win32.MEM_MAPPED:
                Type = "Mapped"
            elif mbiType == win32.MEM_PRIVATE:
                Type = "Private"
            elif mbiType == 0:
                Type = ""
            else:
                Type = "Unknown"

            # Output a row in the table.
            if mappedFilenames:
                FileName = mappedFilenames.get(mbi.BaseAddress, "")
                table.addRow(BaseAddress, RegionSize, State, Protect, Type, FileName)
            else:
                table.addRow(BaseAddress, RegionSize, State, Protect, Type)

        # Return the table output.
        return table.getOutput()


# ------------------------------------------------------------------------------


class DebugLog(StaticClass):
    "Static functions for debug logging."

    @staticmethod
    def log_text(text):
        """
        Log lines of text, inserting a timestamp.

        :param text: Text to log.
        :type  text: str

        :return: Log line.
        :rtype:  str
        """
        if text.endswith("\n"):
            text = text[: -len("\n")]
        # text  = text.replace('\n', '\n\t\t')           # text CSV
        ltime = time.strftime("%X")
        msecs = (time.time() % 1) * 1000
        return "[%s.%04d] %s" % (ltime, msecs, text)
        # return '[%s.%04d]\t%s' % (ltime, msecs, text)  # text CSV

    @classmethod
    def log_event(cls, event, text=None):
        """
        Log lines of text associated with a debug event.

        :param event: Event object.
        :type  event: :class:`~winappdbg.event.Event`

        :param text: (Optional) Text to log. If no text is provided the default
            is to show a description of the event itself.
        :type  text: str

        :return: Log line.
        :rtype:  str
        """
        if not text:
            if event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT:
                what = event.get_exception_description()
                if event.is_first_chance():
                    what = "%s (first chance)" % what
                else:
                    what = "%s (second chance)" % what
                try:
                    address = event.get_fault_address()
                except NotImplementedError:
                    address = event.get_exception_address()
            else:
                what = event.get_event_name()
                address = event.get_thread().get_pc()
            process = event.get_process()
            label = process.get_label_at_address(address)
            address = HexDump.address(address, process.get_bits())
            if label:
                where = "%s (%s)" % (address, label)
            else:
                where = address
            text = "%s at %s" % (what, where)
        text = "pid %d tid %d: %s" % (event.get_pid(), event.get_tid(), text)
        # text = 'pid %d tid %d:\t%s' % (event.get_pid(), event.get_tid(), text)     # text CSV
        return cls.log_text(text)


# ------------------------------------------------------------------------------


class Logger(object):
    """
    Logs text to standard output and/or a text file.

    :ivar logfile: Append messages to this text file.
    :vartype logfile: str or None

    :ivar verbose: ``True`` to print messages to standard output.
    :vartype verbose: bool

    :ivar fd: File object where log messages are printed to.
        ``None`` if no log file is used.
    :vartype fd: file
    """

    def __init__(self, logfile=None, verbose=True):
        """
        :param logfile: Append messages to this text file.
        :type  logfile: str or None

        :param verbose: ``True`` to print messages to standard output.
        :type  verbose: bool
        """
        self.verbose = verbose
        self.logfile = logfile
        if self.logfile:
            self.fd = open(self.logfile, "a+", encoding="utf-8")
        else:
            self.fd = None

    def __logfile_error(self, e):
        """
        Shows an error message to standard error
        if the log file can't be written to.

        Used internally.

        :param e: Exception raised when trying to write to the log file.
        :type  e: Exception
        """
        from sys import stderr

        msg = "Warning, error writing log file %s: %s\n"
        msg = msg % (self.logfile, str(e))
        stderr.write(DebugLog.log_text(msg))
        self.logfile = None
        self.fd = None

    def __do_log(self, text):
        """
        Writes the given text verbatim into the log file (if any)
        and/or standard input (if the verbose flag is turned on).

        Used internally.

        :param text: Text to print.
        :type  text: str
        """
        if self.verbose:
            print(text)
        if self.logfile and self.fd:
            try:
                self.fd.write("%s\n" % text)
                self.fd.flush()
            except IOError as e:
                self.__logfile_error(e)

    def log_text(self, text):
        """
        Log lines of text, inserting a timestamp.

        :param text: Text to log.
        :type  text: str
        """
        self.__do_log(DebugLog.log_text(text))

    def log_event(self, event, text=None):
        """
        Log lines of text associated with a debug event.

        :param event: Event object.
        :type  event: :class:`~winappdbg.event.Event`

        :param text: (Optional) Text to log. If no text is provided the default
            is to show a description of the event itself.
        :type  text: str
        """
        self.__do_log(DebugLog.log_event(event, text))

    def log_exc(self):
        """
        Log lines of text associated with the last Python exception.
        """
        self.__do_log("Exception raised: %s" % traceback.format_exc())

    def is_enabled(self):
        """
        Determines if the logger will actually print anything when the ``log_*``
        methods are called.

        This may save some processing if the log text requires a lengthy
        calculation to prepare. If no log file is set and stdout logging
        is disabled, there's no point in preparing a log text that won't
        be shown to anyone.

        :return: ``True`` if a log file was set and/or standard output logging
            is enabled, or ``False`` otherwise.
        :rtype:  bool
        """
        return self.verbose or (self.logfile is not None)
