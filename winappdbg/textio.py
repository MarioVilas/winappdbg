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

"""
Functions for text input, logging or text output.

@group Input:
    HexInput
@group Output:
    HexDump,
    CrashDump,
    DebugLog
"""

__all__ =   [
                'DebugLog',
                'HexDump',
                'HexInput',
                'CrashDump',
            ]

import time
import struct

class DebugLog (object):
    'Static functions for debug logging.'

    @staticmethod
    def log_text(text):
        'Log lines of text, inserting a timestamp.'
        if text.endswith('\n'):
            text = text[:-len('\n')]
        #text  = text.replace('\n', '\n\t\t')           # text CSV
        ltime = time.strftime("%X")
        msecs = (time.time() % 1) * 1000
        return '[%s.%04d] %s' % (ltime, msecs, text)
        #return '[%s.%04d]\t%s' % (ltime, msecs, text)  # text CSV

    @classmethod
    def log_event(cls, event, text):
        'Log lines of text associated with a debug event.'
        text = 'pid %d tid %d: %s' % (event.get_pid(), event.get_tid(), text)
        #text = 'pid %d tid %d:\t%s' % (event.get_pid(), event.get_tid(), text)     # text CSV
        return cls.log_text(text)

#------------------------------------------------------------------------------

class HexDump (object):
    'Static functions for hexadecimal dumps.'

    @staticmethod
    def printable(data):
        'Replace unprintable characters with dots.'
        result = ''
        for c in data:
            if 32 < ord(c) < 128:
                result += c
            else:
                result += '.'
        return result

    @staticmethod
    def hexadecimal(data, separator = ''):
        'Convert binary data to a string of hexadecimal numbers.'
        return separator.join( [ '%.2x' % ord(c) for c in data ] )

    @classmethod
    def hexline(cls, data, separator = ' ', width = None):
        'Dump a line of hexadecimal numbers from binary data.'
        if width is None:
            fmt = '%s  %s\n'
        else:
            fmt = '%%-%ds  %%-%ds\n' % ((len(separator)+2)*width-1, width)
        return fmt % (cls.hexadecimal(data, separator), cls.printable(data))

    @classmethod
    def hexblock(cls, data, address = None, separator = ' ', width = 16):
        'Dump a block of hexadecimal numbers from binary data.'
        result = ''
        if address is None:
            for i in xrange(0, len(data), width):
                result  += cls.hexline(data[i:i+width], separator, width)
        else:
            for i in xrange(0, len(data), width):
                line     = cls.hexline(data[i:i+width], separator, width)
                result  += '%.8x: %s' % (address, line)
                address += width
        return result

#------------------------------------------------------------------------------

class HexInput (object):
    'Static functions for hexadecimal user input.'

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
            result = int(token[2:], 16) # hexadecimal
        elif token.startswith('0b'):
            result = int(token[2:], 2)  # binary
        elif token.startswith('0'):
            result = int(token, 8)      # octal
        else:
            result = int(token)         # decimal
        return result

    @staticmethod
    def binary(token):
        """
        Convert a strip of hexadecimal numbers into binary data.
        
        @type  token: str
        @param token: String to parse.
        
        @rtype:  str
        @return: Parsed string value.
        """
        token = token.replace(' ', '')
        token = token.replace('\t', '')
        token = token.replace('\r', '')
        token = token.replace('\n', '')
        if len(token) % 2 != 0:
            raise ValueError, "Missing characters in hex data"
        data = ''
        for i in xrange(0, len(token), 2):
            x = token[i:i+2]
            d = int(x, 16)
            s = struct.pack('<B', d)
            data += s
        return data

    @classmethod
    def integer_list_file(cls, filename):
        """
        Read a list of integers from a file.
        
        The file format is:
        
         - # begins comments
         - leading and trailing spaces are ignored
         - integers can be specified as:
            - decimal numbers ("100" is 100)
            - hexadecimal numbers ("0x100" is 256)
            - binary numbers ("0b100" is 4)
            - octal numbers ("0100" is 64)
        
        @type  filename: str
        @param filename: Name of the file to read.
        
        @rtype:  list( int )
        @return: List of integers read from file.
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
    def mixed_list_file(cls, filename):
        """
        Read a list of mixed values from a file.
        
        The file format is:
        
         - # begins comments
         - leading and trailing spaces are ignored
         - strings cannot span over a single line
         - integers can be specified as:
            - decimal numbers ("100" is 100)
            - hexadecimal numbers ("0x100" is 256)
            - binary numbers ("0b100" is 4)
            - octal numbers ("0100" is 64)
        
        @type  filename: str
        @param filename: Name of the file to read.
        
        @rtype:  list
        @return: List of integers and strings read from file.
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
            result += '%s -> %s' % (tag, dumped)
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
                result += '%s -> %s' % (tag, dumped)
        return result

    @staticmethod
    def dump_stack_trace(stack_trace):
        """
        Dump a stack trace.
        
        @type  stack_trace: list( int, int, str )
        @param stack_trace: Stack trace as a tuple of
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

    # TODO
    # Instead of a star when EIP points to, it would be better to show
    # any register value (or other values like the exception address) that
    # points to a location in the dissassembled code.
    @staticmethod
    def dump_code(disassembly, pc = None, bLowercase = True):
        """
        Dump a disassembly. Optionally mark where the program counter is.
        
        @type  disassembly: tuple( int, int, str, str )
        @param disassembly: Disassembly dump as returned by
            L{Process.disassemble} or L{Thread.disassemble_around_pc}.
        
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
