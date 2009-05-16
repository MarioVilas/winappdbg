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

"""
Functions for text input, logging or text output.

@group Input:
    HexInput
@group Output:
    HexOutput
@group Logging:
    HexDump,
    CrashDump,
    DebugLog
"""

__revision__ = "$Id$"

__all__ =   [
                'DebugLog',
                'HexDump',
                'HexInput',
                'HexOutput',
                'CrashDump',
            ]

import win32

import time
import struct

#------------------------------------------------------------------------------

class HexInput (object):
    """
    Static functions for user input parsing.
    The counterparts for each method are in the L{HexOutput} class.
    """

    @staticmethod
    def integer(token):
        """
        Convert numeric strings into integers.

        @type  token: str
        @param token: String to parse.

        @rtype:  int
        @return: Parsed integer value.
        """
        token = token.strip()
        if token.startswith('0x'):
            result = int(token, 16)     # hexadecimal
        elif token.startswith('0b'):
            result = int(token[2:], 2)  # binary
##        elif token.startswith('0'):
##            result = int(token, 8)      # octal
        else:
            try:
                result = int(token)     # decimal
            except ValueError:
                result = int(token, 16) # hexadecimal (no "0x" prefix)
        return result

    @staticmethod
    def address(token):
        """
        Convert numeric strings into memory addresses.

        @type  token: str
        @param token: String to parse.

        @rtype:  int
        @return: Parsed integer value.
        """
        return int(token, 16)

    @staticmethod
    def hexadecimal(token):
        """
        Convert a strip of hexadecimal numbers into binary data.

        @type  token: str
        @param token: String to parse.

        @rtype:  str
        @return: Parsed string value.
        """
        token = ''.join([ c for c in token if c.isalnum() ])
        if len(token) % 2 != 0:
            raise ValueError, "Missing characters in hex data"
        data = ''
        for i in xrange(0, len(token), 2):
            x = token[i:i+2]
            d = int(x, 16)
            s = struct.pack('<B', d)
            data += s
        return data

    @staticmethod
    def pattern(token):
        """
        Convert an hexadecimal search pattern into a POSIX regular expression.

        For example, the following pattern::

            "B8 0? ?0 ?? ??"

        Would match the following data::

            "B8 0D F0 AD BA"    # mov eax, 0xBAADF00D

        @type  token: str
        @param token: String to parse.

        @rtype:  str
        @return: Parsed string value.
        """
        token = ''.join([ c for c in token if c == '?' or c.isalnum() ])
        if len(token) % 2 != 0:
            raise ValueError, "Missing characters in hex data"
        regexp = ''
        for i in xrange(0, len(token), 2):
            x = token[i:i+2]
            if x == '??':
                regexp += '.'
            elif x[0] == '?':
                f = '\\x%%.1x%s' % x[1]
                x = ''.join([ f % c for c in xrange(0, 0x10) ])
                regexp = '%s[%s]' % (regexp, x)
            elif x[1] == '?':
                f = '\\x%s%%.1x' % x[0]
                x = ''.join([ f % c for c in xrange(0, 0x10) ])
                regexp = '%s[%s]' % (regexp, x)
            else:
                regexp = '%s\\x%s' % (regexp, x)
        return regexp

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

        @type  filename: str
        @param filename: Name of the file to read.

        @rtype:  list( int )
        @return: List of integers read from the file.
        """
        count  = 0
        result = list()
        fd     = open(filename, 'r')
        for line in fd:
            count = count + 1
            if '#' in line:
                line = line[ : line.find('#') ]
            line = line.strip()
            if line:
                try:
                    value = cls.integer(line)
                except ValueError, e:
                    msg = "Error in line %d of %s: %s"
                    msg = msg % (count, filename, str(e))
                    raise ValueError, msg
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

        @type  filename: str
        @param filename: Name of the file to read.

        @rtype:  list
        @return: List of integers and strings read from the file.
        """
        count  = 0
        result = list()
        fd     = open(filename, 'r')
        for line in fd:
            count = count + 1
            if '#' in line:
                line = line[ : line.find('#') ]
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

        @type  filename: str
        @param filename: Name of the file to read.

        @rtype:  list
        @return: List of integers and strings read from the file.
        """
        count  = 0
        result = list()
        fd     = open(filename, 'r')
        for line in fd:
            count = count + 1
            if '#' in line:
                line = line[ : line.find('#') ]
            line = line.strip()
            if line:
                try:
                    value = cls.integer(line)
                except ValueError, e:
                    value = line
                result.append(value)
        return result

#------------------------------------------------------------------------------

class HexOutput (object):
    """
    Static functions for user output parsing.
    The counterparts for each method are in the L{HexInput} class.
    """

    @staticmethod
    def integer(integer):
        """
        @type  integer: int
        @param integer: Integer.

        @rtype:  str
        @return: Text output.
        """
        return '0x%.8x' % integer

    @staticmethod
    def address(address):
        """
        @type  address: int
        @param address: Memory address.

        @rtype:  str
        @return: Text output.
        """
        return '0x%.8x' % address

    @staticmethod
    def hexadecimal(data):
        """
        Convert binary data to a string of hexadecimal numbers.

        @type  data: str
        @param data: Binary data.

        @rtype:  str
        @return: Hexadecimal representation.
        """
        return HexDump.hexadecimal(data, separator = '')

    @classmethod
    def integer_list_file(cls, filename, values):
        """
        Write a list of integers to a file.
        If a file of the same name exists, it's contents are replaced.

        See L{HexInput.integer_list_file} for a description of the file format.

        @type  filename: str
        @param filename: Name of the file to write.

        @type  values: list( int )
        @param values: List of integers to write to the file.
        """
        fd = open(filename, 'w')
        for integer in values:
            print >> fd, cls.integer(integer)
        fd.close()

    @classmethod
    def string_list_file(cls, filename, values):
        """
        Write a list of strings to a file.
        If a file of the same name exists, it's contents are replaced.

        See L{HexInput.string_list_file} for a description of the file format.

        @type  filename: str
        @param filename: Name of the file to write.

        @type  values: list( int )
        @param values: List of strings to write to the file.
        """
        fd = open(filename, 'w')
        for string in values:
            print >> fd, string
        fd.close()

    @classmethod
    def mixed_list_file(cls, filename, values):
        """
        Write a list of mixed values to a file.
        If a file of the same name exists, it's contents are replaced.

        See L{HexInput.mixed_list_file} for a description of the file format.

        @type  filename: str
        @param filename: Name of the file to write.

        @type  values: list( int )
        @param values: List of mixed values to write to the file.
        """
        fd = open(filename, 'w')
        for original in values:
            try:
                parsed = cls.integer(original)
            except TypeError:
                parsed = repr(original)
            print >> fd, parsed
        fd.close()

#------------------------------------------------------------------------------

class DebugLog (object):
    'Static functions for debug logging.'

    @staticmethod
    def log_text(text):
        """
        Log lines of text, inserting a timestamp.

        @type  text: str
        @param text: Text to log.

        @rtype:  str
        @return: Log line.
        """
        if text.endswith('\n'):
            text = text[:-len('\n')]
        #text  = text.replace('\n', '\n\t\t')           # text CSV
        ltime = time.strftime("%X")
        msecs = (time.time() % 1) * 1000
        return '[%s.%04d] %s' % (ltime, msecs, text)
        #return '[%s.%04d]\t%s' % (ltime, msecs, text)  # text CSV

    @classmethod
    def log_event(cls, event, text):
        """
        Log lines of text associated with a debug event.

        @type  event: L{Event}
        @param event: Event object.

        @type  text: str
        @param text: Text to log.

        @rtype:  str
        @return: Log line.
        """
        text = 'pid %d tid %d: %s' % (event.get_pid(), event.get_tid(), text)
        #text = 'pid %d tid %d:\t%s' % (event.get_pid(), event.get_tid(), text)     # text CSV
        return cls.log_text(text)

#------------------------------------------------------------------------------

class HexDump (object):
    'Static functions for hexadecimal dumps.'

    @staticmethod
    def printable(data):
        """
        Replace unprintable characters with dots.

        @type  data: str
        @param data: Binary data.

        @rtype:  str
        @return: Printable text.
        """
        result = ''
        for c in data:
            if 32 < ord(c) < 128:
                result += c
            else:
                result += '.'
        return result

    @staticmethod
    def hexadecimal(data, separator = ''):
        """
        Convert binary data to a string of hexadecimal numbers.

        @type  data: str
        @param data: Binary data.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each character.

        @rtype:  str
        @return: Hexadecimal representation.
        """
        return separator.join( [ '%.2x' % ord(c) for c in data ] )

    @staticmethod
    def hexa_word(data, separator = ' '):
        """
        Convert binary data to a string of hexadecimal WORDs.

        @type  data: str
        @param data: Binary data.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each WORD.

        @rtype:  str
        @return: Hexadecimal representation.
        """
        if len(data) & 1 != 0:
            data += '\0'
        return separator.join( [ '%.4x' % struct.unpack('<H', data[i:i+2])[0] \
                                           for i in xrange(0, len(data), 2) ] )

    @staticmethod
    def hexa_dword(data, separator = ' '):
        """
        Convert binary data to a string of hexadecimal DWORDs.

        @type  data: str
        @param data: Binary data.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each DWORD.

        @rtype:  str
        @return: Hexadecimal representation.
        """
        if len(data) & 3 != 0:
            data += '\0' * (4 - (len(data) & 3))
        return separator.join( [ '%.8x' % struct.unpack('<L', data[i:i+4])[0] \
                                           for i in xrange(0, len(data), 4) ] )

    @staticmethod
    def hexa_qword(data, separator = ' '):
        """
        Convert binary data to a string of hexadecimal QWORDs.

        @type  data: str
        @param data: Binary data.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each QWORD.

        @rtype:  str
        @return: Hexadecimal representation.
        """
        if len(data) & 7 != 0:
            data += '\0' * (8 - (len(data) & 7))
        return separator.join( [ '%.16x' % struct.unpack('<Q', data[i:i+8])[0]\
                                           for i in xrange(0, len(data), 8) ] )

    @classmethod
    def hexline(cls, data, separator = ' ', width = None):
        """
        Dump a line of hexadecimal numbers from binary data.

        @type  data: str
        @param data: Binary data.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each character.

        @type  width: int
        @param width:
            (Optional) Maximum number of characters to convert per text line.
            This value is also used for padding.

        @rtype:  str
        @return: Multiline output text.
        """
        if width is None:
            fmt = '%s  %s'
        else:
            fmt = '%%-%ds  %%-%ds' % ((len(separator)+2)*width-1, width)
        return fmt % (cls.hexadecimal(data, separator), cls.printable(data))

    @classmethod
    def hexblock(cls, data, address = None, separator = ' ', width = 8):
        """
        Dump a block of hexadecimal numbers from binary data.
        Also show a printable text version of the data.

        @type  data: str
        @param data: Binary data.

        @type  address: str
        @param address: Memory address where the data was read from.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each character.

        @type  width: int
        @param width:
            (Optional) Maximum number of characters to convert per text line.

        @rtype:  str
        @return: Multiline output text.
        """
        return cls.hexblock_cb(cls.hexline, data, address, width * 2,
                 cb_kwargs = {'width':width * 2, 'separator': separator})

    @classmethod
    def hexblock_cb(cls, callback, data, address = None, width = 16,
                                                cb_args = (), cb_kwargs = {}):
        """
        Dump a block of binary data using a callback function to convert each
        line of text.

        @type  callback: function
        @param callback: Callback function to convert each line of data.

        @type  data: str
        @param data: Binary data.

        @type  address: str
        @param address:
            (Optional) Memory address where the data was read from.

        @type  cb_args: str
        @param cb_args:
            (Optional) Arguments to pass to the callback function.

        @type  cb_kwargs: str
        @param cb_kwargs:
            (Optional) Keyword arguments to pass to the callback function.

        @type  width: int
        @param width:
            (Optional) Maximum number of bytes to convert per text line.

        @rtype:  str
        @return: Multiline output text.
        """
        result = ''
        if address is None:
            for i in xrange(0, len(data), width):
                result = '%s%s\n' % ( result, \
                             callback(data[i:i+width], *cb_args, **cb_kwargs) )
        else:
            for i in xrange(0, len(data), width):
                result = '%s%s: %s\n' % ( result, cls.address(address), \
                             callback(data[i:i+width], *cb_args, **cb_kwargs) )
                address += width
        return result

    @classmethod
    def hexblock_byte(cls, data, address = None, separator = ' ', width = 16):
        """
        Dump a block of hexadecimal BYTEs from binary data.

        @type  data: str
        @param data: Binary data.

        @type  address: str
        @param address: Memory address where the data was read from.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each BYTE.

        @type  width: int
        @param width:
            (Optional) Maximum number of BYTEs to convert per text line.

        @rtype:  str
        @return: Multiline output text.
        """
        return cls.hexblock_cb(cls.hexadecimal, data, address, width,
                                          cb_kwargs = {'separator': separator})

    @classmethod
    def hexblock_word(cls, data, address = None, separator = ' ', width = 8):
        """
        Dump a block of hexadecimal WORDs from binary data.

        @type  data: str
        @param data: Binary data.

        @type  address: str
        @param address: Memory address where the data was read from.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each WORD.

        @type  width: int
        @param width:
            (Optional) Maximum number of WORDs to convert per text line.

        @rtype:  str
        @return: Multiline output text.
        """
        return cls.hexblock_cb(cls.hexa_word, data, address, width * 2,
                                          cb_kwargs = {'separator': separator})

    @classmethod
    def hexblock_dword(cls, data, address = None, separator = ' ', width = 4):
        """
        Dump a block of hexadecimal DWORDs from binary data.

        @type  data: str
        @param data: Binary data.

        @type  address: str
        @param address: Memory address where the data was read from.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each DWORD.

        @type  width: int
        @param width:
            (Optional) Maximum number of DWORDs to convert per text line.

        @rtype:  str
        @return: Multiline output text.
        """
        return cls.hexblock_cb(cls.hexa_dword, data, address, width * 4,
                                          cb_kwargs = {'separator': separator})

    @classmethod
    def hexblock_qword(cls, data, address = None, separator = ' ', width = 2):
        """
        Dump a block of hexadecimal QWORDs from binary data.

        @type  data: str
        @param data: Binary data.

        @type  address: str
        @param address: Memory address where the data was read from.

        @type  separator: str
        @param separator:
            Separator between the hexadecimal representation of each QWORD.

        @type  width: int
        @param width:
            (Optional) Maximum number of QWORDs to convert per text line.

        @rtype:  str
        @return: Multiline output text.
        """
        return cls.hexblock_cb(cls.hexa_qword, data, address, width * 8,
                                          cb_kwargs = {'separator': separator})

    @staticmethod
    def address(address):
        """
        @type  address: int
        @param address: Memory address.

        @rtype:  str
        @return: Text output.
        """
        return '%.8x' % address

    @staticmethod
    def integer(integer):
        """
        @type  integer: int
        @param integer: Integer.

        @rtype:  str
        @return: Text output.
        """
        return '%11i' % integer

#------------------------------------------------------------------------------

class CrashDump (object):
    """
    Static functions for crash dumps.

    @type reg_template: str
    @cvar reg_template: Template for the L{dump_registers} method.
    """

    # Template for the dump_registers method.
    reg_template = (
        'eax=%(Eax).8x ebx=%(Ebx).8x ecx=%(Ecx).8x edx=%(Edx).8x esi=%(Esi).8x edi=%(Edi).8x\n'
        'eip=%(Eip).8x esp=%(Esp).8x ebp=%(Ebp).8x %(efl_dump)s\n'
        'cs=%(SegCs).4x  ss=%(SegSs).4x  ds=%(SegDs).4x  es=%(SegEs).4x  fs=%(SegFs).4x  gs=%(SegGs).4x             efl=%(EFlags).8x\n'
        )

    @staticmethod
    def dump_flags(efl):
        """
        Dump the x86 processor flags.
        The output mimics that of the WinDBG debugger.

        @type  efl: int
        @param efl: Value of the eFlags register.

        @rtype:  str
        @return: Text suitable for logging.
        """
        if efl is None:
            return ''
        efl_dump = 'iopl=%1d' % ((efl & 0x3000) >> 12)
        if efl & 0x100000:
            efl_dump += ' vip'
        else:
            efl_dump += '    '
        if efl & 0x80000:
            efl_dump += ' vif'
        else:
            efl_dump += '    '
        # 0x20000 ???
        if efl & 0x800:
            efl_dump += ' ov'       # Overflow
        else:
            efl_dump += ' no'       # No overflow
        if efl & 0x400:
            efl_dump += ' dn'       # Downwards
        else:
            efl_dump += ' up'       # Upwards
        if efl & 0x200:
            efl_dump += ' ei'       # Enable interrupts
        else:
            efl_dump += ' di'       # Disable interrupts
        # 0x100 trap flag
        if efl & 0x80:
            efl_dump += ' ng'       # Negative
        else:
            efl_dump += ' pl'       # Positive
        if efl & 0x40:
            efl_dump += ' zr'       # Zero
        else:
            efl_dump += ' nz'       # Nonzero
        if efl & 0x10:
            efl_dump += ' ac'       # Auxiliary carry
        else:
            efl_dump += ' na'       # No auxiliary carry
        # 0x8 ???
        if efl & 0x4:
            efl_dump += ' pe'       # Parity odd
        else:
            efl_dump += ' po'       # Parity even
        # 0x2 ???
        if efl & 0x1:
            efl_dump += ' cy'       # Carry
        else:
            efl_dump += ' nc'       # No carry
        return efl_dump

    @classmethod
    def dump_registers(cls, registers):
        """
        Dump the x86 processor register values.
        The output mimics that of the WinDBG debugger.

        @type  registers: dict( str S{->} int )
        @param registers: Dictionary mapping register names to their values.

        @rtype:  str
        @return: Text suitable for logging.
        """
        if registers is None:
            return ''
        registers = registers.copy()
        registers['efl_dump'] = cls.dump_flags( registers['EFlags'] )
        return cls.reg_template % registers

    @staticmethod
    def dump_registers_peek(registers, data, separator = ' ', width = 16):
        """
        Dump data pointed to by the given registers, if any.

        @type  registers: dict( str S{->} int )
        @param registers: Dictionary mapping register names to their values.

        @type  data: dict( str S{->} str )
        @param data: Dictionary mapping register names to the data they point to.

        @rtype:  str
        @return: Text suitable for logging.
        """
        if None in (registers, data):
            return ''
        names = data.keys()
        names.sort()
        result = ''
        for reg_name in names:
            tag     = reg_name
    ##        value   = registers[reg_name]
            dumped  = HexDump.hexline(data[reg_name], separator, width)
    ##        result += '%s->%.8x: %s' % (tag, value, dumped)
            result += '%s -> %s\n' % (tag, dumped)
        return result

    @staticmethod
    def dump_data_peek(data, base = 0, separator = ' ', width = 16):
        """
        Dump data from pointers guessed within the given binary data.

        @type  data: str
        @param data: Dictionary mapping offsets to the data they point to.

        @type  base: int
        @param base: Base offset.

        @rtype:  str
        @return: Text suitable for logging.
        """
        if data is None:
            return ''
        pointers = data.keys()
        pointers.sort()
        result = ''
        for offset in pointers:
            dumped  = HexDump.hexline(data[offset], separator, width)
            result += '%.8x -> %s' % (base + offset, dumped)
        return result

    @staticmethod
    def dump_stack_peek(data, separator = ' ', width = 16):
        """
        Dump data from pointers guessed within the given stack dump.

        @type  data: str
        @param data: Dictionary mapping stack offsets to the data they point to.

        @rtype:  str
        @return: Text suitable for logging.
        """
        if data is None:
            return ''
        pointers = data.keys()
        pointers.sort()
        result = ''
        if pointers:
            tag_fmt = '[esp+0x%%.%dx]' % (len( '%x' % pointers[-1] ) )
            for offset in pointers:
                dumped  = HexDump.hexline(data[offset], separator, width)
                tag     = tag_fmt % offset
                result += '%s -> %s\n' % (tag, dumped)
        return result

    @staticmethod
    def dump_stack_trace(stack_trace):
        """
        Dump a stack trace, as returned by L{Thread.get_stack_trace} with the
        C{bUseLabels} parameter set to C{False}.

        @type  stack_trace: list( int, int, str )
        @param stack_trace: Stack trace as a list of tuples of
            ( return address, frame pointer, module filename )

        @rtype:  str
        @return: Text suitable for logging.
        """
        if stack_trace is None:
            return ''
        result = 'Frame pointer  Return address  Module\n'
        for step in stack_trace:
            result += '0x%.8x     0x%.8x      %s\n' % step
        return result

    @staticmethod
    def dump_stack_trace_with_labels(stack_trace):
        """
        Dump a stack trace, as returned by L{Thread.get_stack_trace} with the
        C{bUseLabels} parameter set to C{True}.

        @type  stack_trace: list( int, int, str )
        @param stack_trace: Stack trace as a list of tuples of
            ( return address, frame pointer, module filename )

        @rtype:  str
        @return: Text suitable for logging.
        """
        if stack_trace is None:
            return ''
        max_label  = 0
        for bp, label in stack_trace:
            if len(label) > max_label:
                max_label = len(label)
        if len('Return address') > max_label:
            max_label = len('Return address')
        fmt = '%%s %%-%ds\n' % max_label
        result = fmt % ('Frame pointer ', 'Return address')
        for bp, label in stack_trace:
            bp = '0x%.8x    ' % bp
            result += fmt % (bp, label)
        return result

    # TODO
    # + Instead of a star when EIP points to, it would be better to show
    # any register value (or other values like the exception address) that
    # points to a location in the dissassembled code.
    # + It'd be very useful to show some labels here.
    # + It'd be very useful to show register contents for code at EIP
    @staticmethod
    def dump_code(disassembly, pc = None, bLowercase = True):
        """
        Dump a disassembly. Optionally mark where the program counter is.

        @type  disassembly: list of tuple( int, int, str, str )
        @param disassembly: Disassembly dump as returned by
            L{Process.disassemble} or L{Thread.disassemble_around_pc}.

        @type  pc: int
        @param pc: (Optional) Program counter.

        @type  bLowercase: bool
        @param bLowercase: (Optional) If C{True} convert the code to lowercase.

        @rtype:  str
        @return: Text suitable for logging.
        """
        if disassembly is None:
            return ''
        max_code = 0
        max_dump = 0
        for (addr, size, code, dump) in disassembly:
            if len(code) > max_code:
                max_code = len(code)
            if len(dump) > max_dump:
                max_dump = len(dump)
        fmt = '%%1s 0x%%.8x | %%%ds | %%-%ds\n' % (max_dump, max_code)
        result = ''
        for (addr, size, code, dump) in disassembly:
            if bLowercase:
                code = code.lower()
            if addr == pc:
                star = '*'
            else:
                star = ' '
            result += fmt % (star, addr, dump, code)
        return result

    @staticmethod
    def dump_code_line(disassembly_line,                  bShowAddress = True,
                                                            bLowercase = True):
        """
        Dump a single line of code. To dump a block of code use L{dump_code}.

        @type  disassembly_line: tuple( int, int, str, str )
        @param disassembly_line: Single item of the list returned by
            L{Process.disassemble} or L{Thread.disassemble_around_pc}.

        @type  bShowAddress: int
        @param bShowAddress: (Optional) If C{True} show the memory address.

        @type  bLowercase: bool
        @param bLowercase: (Optional) If C{True} convert the code to lowercase.

        @rtype:  str
        @return: Text suitable for logging.
        """
        (addr, size, code, dump) = disassembly_line
        dump = dump.replace(' ', '')
        if bLowercase:
            code = code.lower()
        if bShowAddress:
            result = '%.8x %-16s %s' % (addr, dump, code)
        else:
            result = '%-16s %s' % (dump, code)
        return result

    @staticmethod
    def dump_memory_map(memoryMap):
        """
        Dump the memory map of a process.

        @type  memoryMap: list( L{MEMORY_BASIC_INFORMATION} )
        @param memoryMap: Memory map returned by L{Process.get_memory_map}.

        @rtype:  str
        @return: Text suitable for logging.
        """

        # Output the header of the table.
        output = "Address   \tSize      \tState     \tAccess    \tType\n"

        # For each memory block in the map...
        for mbi in memoryMap:

            # Address and size of memory block.
            BaseAddress = "0x%.08x" % mbi.BaseAddress
            RegionSize  = "0x%.08x" % mbi.RegionSize

            # State (free or allocated).
            if   mbi.State == win32.MEM_RESERVE:
                State   = "Reserved  "
            elif mbi.State == win32.MEM_COMMIT:
                State   = "Commited  "
            elif mbi.State == win32.MEM_FREE:
                State   = "Free      "
            else:
                State   = "Unknown   "

            # Page protection bits (R/W/X/G).
            if mbi.State != win32.MEM_COMMIT:
                Protect = "          "
            else:
    ##            Protect = "0x%.08x" % mbi.Protect
                if   mbi.Protect & win32.PAGE_NOACCESS:
                    Protect = "--- "
                elif mbi.Protect & win32.PAGE_READONLY:
                    Protect = "R-- "
                elif mbi.Protect & win32.PAGE_READWRITE:
                    Protect = "RW- "
                elif mbi.Protect & win32.PAGE_WRITECOPY:
                    Protect = "RC- "
                elif mbi.Protect & win32.PAGE_EXECUTE:
                    Protect = "--X "
                elif mbi.Protect & win32.PAGE_EXECUTE_READ:
                    Protect = "R-- "
                elif mbi.Protect & win32.PAGE_EXECUTE_READWRITE:
                    Protect = "RW- "
                elif mbi.Protect & win32.PAGE_EXECUTE_WRITECOPY:
                    Protect = "RCX "
                else:
                    Protect = "??? "
                if   mbi.Protect & win32.PAGE_GUARD:
                    Protect += "G"
                else:
                    Protect += "-"
                if   mbi.Protect & win32.PAGE_NOCACHE:
                    Protect += "N"
                else:
                    Protect += "-"
                if   mbi.Protect & win32.PAGE_WRITECOMBINE:
                    Protect += "W"
                else:
                    Protect += "-"
                Protect += "   "

            # Type (file mapping, executable image, or private memory).
            if   mbi.Type == win32.MEM_IMAGE:
                Type    = "Image     "
            elif mbi.Type == win32.MEM_MAPPED:
                Type    = "Mapped    "
            elif mbi.Type == win32.MEM_PRIVATE:
                Type    = "Private   "
            elif mbi.Type == 0:
                Type    = "          "
            else:
                Type    = "Unknown   "

            # Output a row in the table.
            fmt = "%s\t%s\t%s\t%s\t%s\n"
            output += fmt % ( BaseAddress, RegionSize, State, Protect, Type )

        # Return the output table.
        return output
