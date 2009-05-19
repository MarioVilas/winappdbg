# :[diStorm64}: Python binding
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

info = (
    ":[diStorm64}: by Gil Dabah, http://ragestorm.net/distorm/\n"
    "Python binding by Mario Vilas, http://breakingcode.wordpress.com/\n"
)

__revision__ = "$Id$"

__all__ = [
    'Decode',
    'DecodeGenerator',
    'Decode16Bits',
    'Decode32Bits',
    'Decode64Bits',
]

from ctypes import *

#==============================================================================
# Load the diStorm DLL

# Guess the DLL filename and load the library.
# Set the 64 bit support constant accordingly.
try:
    _distorm = cdll.LoadLibrary('distorm64.dll')
    SUPPORT_64BIT_OFFSET = True
except OSError:
    try:
        _distorm = cdll.LoadLibrary('libdistorm64.so')
        SUPPORT_64BIT_OFFSET = True
    except OSError:
        try:
            _distorm = cdll.LoadLibrary('distorm32.dll')
            SUPPORT_64BIT_OFFSET = False
        except OSError:
            try:
                _distorm = cdll.LoadLibrary('libdistorm32.so')
                SUPPORT_64BIT_OFFSET = False
            except OSError:
                raise ImportError("Error loading distorm")

# Get the decode C function.
try:
    if SUPPORT_64BIT_OFFSET:
        internal_decode = _distorm.distorm_decode64
    else:
        internal_decode = _distorm.distorm_decode32
except AttributeError:
    try:
        internal_decode = _distorm.internal_decode
    except AttributeError:
        raise ImportError("Error loading distorm")

#==============================================================================
# diStorm C interface

MAX_TEXT_SIZE       = 60
MAX_INSTRUCTIONS    = 1000

DECRES_NONE         = 0
DECRES_SUCCESS      = 1
DECRES_MEMORYERR    = 2
DECRES_INPUTERR     = 3

if SUPPORT_64BIT_OFFSET:
    _OffsetType = c_ulonglong
else:
    _OffsetType = c_uint

class _WString (Structure):
    _fields_ = [
        ('length',  c_uint),
        ('p',       c_char * MAX_TEXT_SIZE),
    ]

class _DecodedInst (Structure):
    _fields_ = [
        ('mnemonic',        _WString),
        ('operands',        _WString),
        ('instructionHex',  _WString),
        ('size',            c_uint),
        ('offset',          _OffsetType),
    ]

#==============================================================================
# diStorm Python interface

Decode16Bits    = 0     # 80286 decoding
Decode32Bits    = 1     # IA-32 decoding
Decode64Bits    = 2     # AMD64 decoding
OffsetTypeSize  = sizeof(_OffsetType) * 8

def DecodeGenerator(codeOffset, code, dt):
    """
    @type  codeOffset: long
    @param codeOffset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  dt: int
    @param dt: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  generator of tuple( long, int, str, str )
    @return: Generator of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """

    if not code:
        return

    if not codeOffset:
        codeOffset = 0

    if dt not in (Decode16Bits, Decode32Bits, Decode64Bits):
        raise ValueError("Invalid decode type value: %r" % (dt,))

    codeLen         = len(code)
    code            = create_string_buffer(code)
    p_code          = addressof(code)
    result          = (_DecodedInst * MAX_INSTRUCTIONS)()
    p_result        = byref(result)

    while codeLen > 0:

        usedInstructionsCount = c_uint(0)
        status = internal_decode(_OffsetType(codeOffset), p_code, codeLen, dt,
                     p_result, MAX_INSTRUCTIONS, byref(usedInstructionsCount))
        if status == DECRES_INPUTERR:
            raise ValueError("Invalid arguments passed to distorm_decode()")

        used = usedInstructionsCount.value
        if not used:
            break
        used = used - 1

        for index in range(used):
            di   = result[index]
            asm  = '%s %s' % (di.mnemonic.p, di.operands.p)
            pydi = ( di.offset, di.size, asm, di.instructionHex.p )
            yield pydi

        di         = result[used]
        delta      = di.offset - codeOffset
        if delta <= 0:
            break
        codeOffset = codeOffset + delta
        p_code     = p_code + delta
        codeLen    = codeLen - delta

def Decode(offset, code, type = Decode32Bits):
    """
    @type  offset: long
    @param offset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  type: int
    @param type: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  list of tuple( long, int, str, str )
    @return: List of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """
    return list( DecodeGenerator(offset, code, type) )

#==============================================================================
# Example code

if __name__ == '__main__':
    import sys
    import optparse

    # uncomment to test with distorm.pyd
##    from distorm import *

    # Parse the command line arguments
    usage  = 'Usage: %prog [--b16 | --b32 | --b64] filename [offset]'
    parser = optparse.OptionParser(usage=usage)
    parser.add_option(  '--b16', help='80286 decoding',
                        action='store_const', dest='dt', const=Decode16Bits  )
    parser.add_option(  '--b32', help='IA-32 decoding [default]',
                        action='store_const', dest='dt', const=Decode32Bits  )
    parser.add_option(  '--b64', help='AMD64 decoding',
                        action='store_const', dest='dt', const=Decode64Bits  )
    parser.set_defaults(dt=Decode32Bits)
    options, args = parser.parse_args(sys.argv)
    if len(args) < 2:
        parser.error('missing parameter: filename')
    filename = args[1]
    offset   = 0
    length   = None
    if len(args) == 3:
        try:
            offset = int(args[2], 10)
        except ValueError:
            parser.error('invalid offset: %s' % args[2])
        if offset < 0:
            parser.error('invalid offset: %s' % args[2])
    elif len(args) > 3:
        parser.error('too many parameters')

    # Read the code from the file
    try:
        code = open(filename, 'rb').read()
    except Exception as e:
        parser.error('error reading file %s: %s' % (filename, e))

    # Print each decoded instruction
    try:
        generator = DecodeGenerator
    except NameError:
        generator = Decode
    iterable = generator(offset, code, options.dt)
    for (offset, size, instruction, hexdump) in iterable:
        print("%.8x: %-32s %s" % (offset, hexdump, instruction))
