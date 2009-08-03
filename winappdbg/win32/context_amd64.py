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
Debugging API wrappers in ctypes.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/Win32APIWrappers}
"""

__revision__ = "$Id$"

from defines import *

# The following values specify the type of access in the first parameter
# of the exception record whan the exception code specifies an access
# violation.
EXCEPTION_READ_FAULT        = 0     # exception caused by a read
EXCEPTION_WRITE_FAULT       = 1     # exception caused by a write
EXCEPTION_EXECUTE_FAULT     = 8     # exception caused by an instruction fetch

CONTEXT_AMD64           = 0x00100000

CONTEXT_CONTROL         = (CONTEXT_AMD64 | 0x1L)
CONTEXT_INTEGER         = (CONTEXT_AMD64 | 0x2L)
CONTEXT_SEGMENTS        = (CONTEXT_AMD64 | 0x4L)
CONTEXT_FLOATING_POINT  = (CONTEXT_AMD64 | 0x8L)
CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10L)

CONTEXT_MMX_REGISTERS   = CONTEXT_FLOATING_POINT

CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

CONTEXT_ALL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | \
               CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

CONTEXT_EXCEPTION_ACTIVE    = 0x8000000
CONTEXT_SERVICE_ACTIVE      = 0x10000000
CONTEXT_EXCEPTION_REQUEST   = 0x40000000
CONTEXT_EXCEPTION_REPORTING = 0x80000000

INITIAL_MXCSR = 0x1f80            # initial MXCSR value
INITIAL_FPCSR = 0x027f            # initial FPCSR value

# typedef struct _XMM_SAVE_AREA32 {
#     WORD   ControlWord;
#     WORD   StatusWord;
#     BYTE  TagWord;
#     BYTE  Reserved1;
#     WORD   ErrorOpcode;
#     DWORD ErrorOffset;
#     WORD   ErrorSelector;
#     WORD   Reserved2;
#     DWORD DataOffset;
#     WORD   DataSelector;
#     WORD   Reserved3;
#     DWORD MxCsr;
#     DWORD MxCsr_Mask;
#     M128A FloatRegisters[8];
#     M128A XmmRegisters[16];
#     BYTE  Reserved4[96];
# } XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;
class XMM_SAVE_AREA32(Structure):
    _pack_ = 1
    _fields_ = [
        ('ControlWord',     WORD),
        ('StatusWord',      WORD),
        ('TagWord',         BYTE),
        ('Reserved1',       BYTE),
        ('ErrorOpcode',     WORD),
        ('ErrorOffset',     DWORD),
        ('ErrorSelector',   WORD),
        ('Reserved2',       WORD),
        ('DataOffset',      DWORD),
        ('DataSelector',    WORD),
        ('Reserved3',       WORD),
        ('MxCsr',           DWORD),
        ('MxCsr_Mask',      DWORD),
        ('FloatRegisters',  M128A * 8),
        ('XmmRegisters',    M128A * 16),
        ('Reserved4',       BYTE * 96),
    ]

PXMM_SAVE_AREA32 = ctypes.POINTER(XMM_SAVE_AREA32)
LEGACY_SAVE_AREA_LENGTH = sizeof(XMM_SAVE_AREA32)

# //
# // Context Frame
# //
# //  This frame has a several purposes: 1) it is used as an argument to
# //  NtContinue, 2) is is used to constuct a call frame for APC delivery,
# //  and 3) it is used in the user level thread creation routines.
# //
# //
# // The flags field within this record controls the contents of a CONTEXT
# // record.
# //
# // If the context record is used as an input parameter, then for each
# // portion of the context record controlled by a flag whose value is
# // set, it is assumed that that portion of the context record contains
# // valid context. If the context record is being used to modify a threads
# // context, then only that portion of the threads context is modified.
# //
# // If the context record is used as an output parameter to capture the
# // context of a thread, then only those portions of the thread's context
# // corresponding to set flags will be returned.
# //
# // CONTEXT_CONTROL specifies SegSs, Rsp, SegCs, Rip, and EFlags.
# //
# // CONTEXT_INTEGER specifies Rax, Rcx, Rdx, Rbx, Rbp, Rsi, Rdi, and R8-R15.
# //
# // CONTEXT_SEGMENTS specifies SegDs, SegEs, SegFs, and SegGs.
# //
# // CONTEXT_DEBUG_REGISTERS specifies Dr0-Dr3 and Dr6-Dr7.
# //
# // CONTEXT_MMX_REGISTERS specifies the floating point and extended registers
# //     Mm0/St0-Mm7/St7 and Xmm0-Xmm15).
# //
#
# typedef struct DECLSPEC_ALIGN(16) _CONTEXT {
#
#     //
#     // Register parameter home addresses.
#     //
#     // N.B. These fields are for convience - they could be used to extend the
#     //      context record in the future.
#     //
#
#     DWORD64 P1Home;
#     DWORD64 P2Home;
#     DWORD64 P3Home;
#     DWORD64 P4Home;
#     DWORD64 P5Home;
#     DWORD64 P6Home;
#
#     //
#     // Control flags.
#     //
#
#     DWORD ContextFlags;
#     DWORD MxCsr;
#
#     //
#     // Segment Registers and processor flags.
#     //
#
#     WORD   SegCs;
#     WORD   SegDs;
#     WORD   SegEs;
#     WORD   SegFs;
#     WORD   SegGs;
#     WORD   SegSs;
#     DWORD EFlags;
#
#     //
#     // Debug registers
#     //
#
#     DWORD64 Dr0;
#     DWORD64 Dr1;
#     DWORD64 Dr2;
#     DWORD64 Dr3;
#     DWORD64 Dr6;
#     DWORD64 Dr7;
#
#     //
#     // Integer registers.
#     //
#
#     DWORD64 Rax;
#     DWORD64 Rcx;
#     DWORD64 Rdx;
#     DWORD64 Rbx;
#     DWORD64 Rsp;
#     DWORD64 Rbp;
#     DWORD64 Rsi;
#     DWORD64 Rdi;
#     DWORD64 R8;
#     DWORD64 R9;
#     DWORD64 R10;
#     DWORD64 R11;
#     DWORD64 R12;
#     DWORD64 R13;
#     DWORD64 R14;
#     DWORD64 R15;
#
#     //
#     // Program counter.
#     //
#
#     DWORD64 Rip;
#
#     //
#     // Floating point state.
#     //
#
#     union {
#         XMM_SAVE_AREA32 FltSave;
#         struct {
#             M128A Header[2];
#             M128A Legacy[8];
#             M128A Xmm0;
#             M128A Xmm1;
#             M128A Xmm2;
#             M128A Xmm3;
#             M128A Xmm4;
#             M128A Xmm5;
#             M128A Xmm6;
#             M128A Xmm7;
#             M128A Xmm8;
#             M128A Xmm9;
#             M128A Xmm10;
#             M128A Xmm11;
#             M128A Xmm12;
#             M128A Xmm13;
#             M128A Xmm14;
#             M128A Xmm15;
#         };
#     };
#
#     //
#     // Vector registers.
#     //
#
#     M128A VectorRegister[26];
#     DWORD64 VectorControl;
#
#     //
#     // Special debug control registers.
#     //
#
#     DWORD64 DebugControl;
#     DWORD64 LastBranchToRip;
#     DWORD64 LastBranchFromRip;
#     DWORD64 LastExceptionToRip;
#     DWORD64 LastExceptionFromRip;
# } CONTEXT, *PCONTEXT;

class _CONTEXT_FLTSAVE_STRUCT(Structure):
    _fields_ = [
        ('Header',                  M128A * 2),
        ('Legacy',                  M128A * 8),
        ('Xmm0',                    M128A),
        ('Xmm1',                    M128A),
        ('Xmm2',                    M128A),
        ('Xmm3',                    M128A),
        ('Xmm4',                    M128A),
        ('Xmm5',                    M128A),
        ('Xmm6',                    M128A),
        ('Xmm7',                    M128A),
        ('Xmm8',                    M128A),
        ('Xmm9',                    M128A),
        ('Xmm10',                   M128A),
        ('Xmm11',                   M128A),
        ('Xmm12',                   M128A),
        ('Xmm13',                   M128A),
        ('Xmm14',                   M128A),
        ('Xmm15',                   M128A),
    ]
class _CONTEXT_FLTSAVE_UNION(Union):
    _fields_ = [
        ('flt',                     XMM_SAVE_AREA32),
        ('xmm',                     _CONTEXT_FLTSAVE_STRUCT),
    ]

class CONTEXT(Structure):
    _pack_ = 16
    _fields_ = [

        # Register parameter home addresses.
        ('P1Home',                  DWORD64),
        ('P2Home',                  DWORD64),
        ('P3Home',                  DWORD64),
        ('P4Home',                  DWORD64),
        ('P5Home',                  DWORD64),
        ('P6Home',                  DWORD64),

        # Control flags.
        ('ContextFlags',            DWORD),
        ('MxCsr',                   DWORD),

        # Segment Registers and processor flags.
        ('SegCs',                   WORD),
        ('SegDs',                   WORD),
        ('SegEs',                   WORD),
        ('SegFs',                   WORD),
        ('SegGs',                   WORD),
        ('SegSs',                   WORD),
        ('EFlags',                  DWORD),

        # Debug registers.
        ('Dr0',                     DWORD64),
        ('Dr1',                     DWORD64),
        ('Dr2',                     DWORD64),
        ('Dr3',                     DWORD64),
        ('Dr6',                     DWORD64),
        ('Dr7',                     DWORD64),

        # Integer registers.
        ('Rax',                     DWORD64),
        ('Rcx',                     DWORD64),
        ('Rdx',                     DWORD64),
        ('Rbx',                     DWORD64),
        ('Rsp',                     DWORD64),
        ('Rbp',                     DWORD64),
        ('Rsi',                     DWORD64),
        ('Rdi',                     DWORD64),
        ('R8',                      DWORD64),
        ('R9',                      DWORD64),
        ('R10',                     DWORD64),
        ('R11',                     DWORD64),
        ('R12',                     DWORD64),
        ('R13',                     DWORD64),
        ('R14',                     DWORD64),
        ('R15',                     DWORD64),

        # Program counter.
        ('Rip',                     DWORD64),

        # Floating point state.
        ('FltSave',                 _CONTEXT_FLTSAVE_UNION),

        # Vector registers.
        ('VectorRegister',          M128A * 26),
        ('VectorControl',           DWORD64),

        # Special debug control registers.
        ('DebugControl',            DWORD64),
        ('LastBranchToRip',         DWORD64),
        ('LastBranchFromRip',       DWORD64),
        ('LastExceptionToRip',      DWORD64),
        ('LastExceptionFromRip',    DWORD64),
    ]

    _others = ('P1Home', 'P2Home', 'P3Home', 'P4Home', 'P5Home', 'P6Home', \
               'MxCsr', 'VectorRegister', 'VectorControl')
    _control = ('SegSs', 'Rsp', 'SegCs', 'Rip', 'EFlags')
    _integer = ('Rax', 'Rcx', 'Rdx', 'Rbx', 'Rsp', 'Rbp', 'Rsi', 'Rdi', \
                'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15')
    _segments = ('SegDs', 'SegEs', 'SegFs', 'SegGs')
    _debug = ('Dr0', 'Dr1', 'Dr2', 'Dr3', 'Dr6', 'Dr7', \
              'DebugControl', 'LastBranchToRip', 'LastBranchFromRip', \
              'LastExceptionToRip', 'LastExceptionFromRip')
    _mmx = ('Xmm0', 'Xmm1', 'Xmm2', 'Xmm3', 'Xmm4', 'Xmm5', 'Xmm6', 'Xmm7', \
          'Xmm8', 'Xmm9', 'Xmm10', 'Xmm11', 'Xmm12', 'Xmm13', 'Xmm14', 'Xmm15')

    # XXX TODO
    # Convert VectorRegister and Xmm0-Xmm15 to pure Python types!

    @classmethod
    def from_dict(cls, ctx):
        'Instance a new structure from a Python dictionary.'
        ctx = dict(ctx)
        s = cls()
        ContextFlags = ctx['ContextFlags']
        s.ContextFlags = ContextFlags
        for key in cls._others:
            setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in cls._control:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in cls._integer:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in cls._segments:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in cls._debug:
                setattr(s, key, ctx[key])
        if (ContextFlags & CONTEXT_MMX_REGISTERS) == CONTEXT_MMX_REGISTERS:
            xmm = s.FltSave.xmm
            for key in cls._mmx:
                setattr(xmm, key, ctx[key])
        return s

    def to_dict(self):
        'Convert a structure into a Python dictionary.'
        ctx = dict()
        ContextFlags = self.ContextFlags
        ctx['ContextFlags'] = ContextFlags
        for key in self._others:
            ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            for key in self._control:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for key in self._integer:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_SEGMENTS) == CONTEXT_SEGMENTS:
            for key in self._segments:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            for key in self._debug:
                ctx[key] = getattr(self, key)
        if (ContextFlags & CONTEXT_MMX_REGISTERS) == CONTEXT_MMX_REGISTERS:
            xmm = self.FltSave.xmm
            for key in self._mmx:
                ctx[key] = getattr(xmm, key)
        return ctx

PCONTEXT = ctypes.POINTER(CONTEXT)

#--- LDT_ENTRY structure ------------------------------------------------------

# typedef struct _LDT_ENTRY {
#   WORD LimitLow;
#   WORD BaseLow;
#   union {
#     struct {
#       BYTE BaseMid;
#       BYTE Flags1;
#       BYTE Flags2;
#       BYTE BaseHi;
#     } Bytes;
#     struct {
#       DWORD BaseMid  :8;
#       DWORD Type  :5;
#       DWORD Dpl  :2;
#       DWORD Pres  :1;
#       DWORD LimitHi  :4;
#       DWORD Sys  :1;
#       DWORD Reserved_0  :1;
#       DWORD Default_Big  :1;
#       DWORD Granularity  :1;
#       DWORD BaseHi  :8;
#     } Bits;
#   } HighWord;
# } LDT_ENTRY,
#  *PLDT_ENTRY;

class _LDT_ENTRY_BYTES_(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseMid',         BYTE),
        ('Flags1',          BYTE),
        ('Flags2',          BYTE),
        ('BaseHi',          BYTE),
    ]

class _LDT_ENTRY_BITS_(Structure):
    _pack_ = 1
    _fields_ = [
        ('BaseMid',         DWORD,  8),
        ('Type',            DWORD,  5),
        ('Dpl',             DWORD,  2),
        ('Pres',            DWORD,  1),
        ('LimitHi',         DWORD,  4),
        ('Sys',             DWORD,  1),
        ('Reserved_0',      DWORD,  1),
        ('Default_Big',     DWORD,  1),
        ('Granularity',     DWORD,  1),
        ('BaseHi',          DWORD,  8),
    ]

class _LDT_ENTRY_HIGHWORD_(Union):
    _pack_ = 1
    _fields_ = [
        ('Bytes',           _LDT_ENTRY_BYTES_),
        ('Bits',            _LDT_ENTRY_BITS_),
    ]

class LDT_ENTRY(Structure):
    _pack_ = 1
    _fields_ = [
        ('LimitLow',        WORD),
        ('BaseLow',         WORD),
        ('HighWord',        _LDT_ENTRY_HIGHWORD_),
    ]

PLDT_ENTRY = ctypes.POINTER(LDT_ENTRY)
