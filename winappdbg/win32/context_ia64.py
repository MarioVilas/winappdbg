# Copyright (c) 2009-2010, Mario Vilas
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
CONTEXT structure for ia64.
"""

__revision__ = "$Id$"

from defines import *

###############################################################################
##                                                                           ##
##      This is an experimental file for support of Itanium processors.      ##
##      Since I have no way of testing this -Itaniums don't come cheap-      ##
##      it's very likely to break.                                           ##
##                                                                           ##
##      The file kernel32.py has to be edited for this one to be loaded.     ##
##                                                                           ##
##      Try at your own risk. (And tell me how it went!)                     ##
##                                                                           ##
###############################################################################

# The following values specify the type of access in the first parameter
# of the exception record when the exception code specifies an access
# violation.
EXCEPTION_READ_FAULT        = 0     # exception caused by a read
EXCEPTION_WRITE_FAULT       = 1     # exception caused by a write
EXCEPTION_EXECUTE_FAULT     = 2     # exception caused by an instruction fetch

CONTEXT_IA64                    = 0x00080000

CONTEXT_CONTROL                 = (CONTEXT_IA64 | 0x00000001L)
CONTEXT_LOWER_FLOATING_POINT    = (CONTEXT_IA64 | 0x00000002L)
CONTEXT_HIGHER_FLOATING_POINT   = (CONTEXT_IA64 | 0x00000004L)
CONTEXT_INTEGER                 = (CONTEXT_IA64 | 0x00000008L)
CONTEXT_DEBUG                   = (CONTEXT_IA64 | 0x00000010L)
CONTEXT_IA32_CONTROL            = (CONTEXT_IA64 | 0x00000020L)  # Includes StIPSR


CONTEXT_FLOATING_POINT          = (CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT)
CONTEXT_FULL                    = (CONTEXT_CONTROL | CONTEXT_FLOATING_POINT | CONTEXT_INTEGER | CONTEXT_IA32_CONTROL)
CONTEXT_ALL                     = (CONTEXT_CONTROL | CONTEXT_FLOATING_POINT | CONTEXT_INTEGER | CONTEXT_DEBUG | CONTEXT_IA32_CONTROL)

CONTEXT_EXCEPTION_ACTIVE        = 0x8000000
CONTEXT_SERVICE_ACTIVE          = 0x10000000
CONTEXT_EXCEPTION_REQUEST       = 0x40000000
CONTEXT_EXCEPTION_REPORTING     = 0x80000000

# //
# // Context Frame
# //
# //  This frame has a several purposes: 1) it is used as an argument to
# //  NtContinue, 2) it is used to construct a call frame for APC delivery,
# //  3) it is used to construct a call frame for exception dispatching
# //  in user mode, 4) it is used in the user level thread creation
# //  routines, and 5) it is used to to pass thread state to debuggers.
# //
# //  N.B. Because this record is used as a call frame, it must be EXACTLY
# //  a multiple of 16 bytes in length and aligned on a 16-byte boundary.
# //
#
# typedef struct _CONTEXT {
#
#     //
#     // The flags values within this flag control the contents of
#     // a CONTEXT record.
#     //
#     // If the context record is used as an input parameter, then
#     // for each portion of the context record controlled by a flag
#     // whose value is set, it is assumed that that portion of the
#     // context record contains valid context. If the context record
#     // is being used to modify a thread's context, then only that
#     // portion of the threads context will be modified.
#     //
#     // If the context record is used as an IN OUT parameter to capture
#     // the context of a thread, then only those portions of the thread's
#     // context corresponding to set flags will be returned.
#     //
#     // The context record is never used as an OUT only parameter.
#     //
#
#     DWORD ContextFlags;
#     DWORD Fill1[3];         // for alignment of following on 16-byte boundary
#
#     //
#     // This section is specified/returned if the ContextFlags word contains
#     // the flag CONTEXT_DEBUG.
#     //
#     // N.B. CONTEXT_DEBUG is *not* part of CONTEXT_FULL.
#     //
#
#     ULONGLONG DbI0;
#     ULONGLONG DbI1;
#     ULONGLONG DbI2;
#     ULONGLONG DbI3;
#     ULONGLONG DbI4;
#     ULONGLONG DbI5;
#     ULONGLONG DbI6;
#     ULONGLONG DbI7;
#
#     ULONGLONG DbD0;
#     ULONGLONG DbD1;
#     ULONGLONG DbD2;
#     ULONGLONG DbD3;
#     ULONGLONG DbD4;
#     ULONGLONG DbD5;
#     ULONGLONG DbD6;
#     ULONGLONG DbD7;
#
#     //
#     // This section is specified/returned if the ContextFlags word contains
#     // the flag CONTEXT_LOWER_FLOATING_POINT.
#     //
#
#     FLOAT128 FltS0;
#     FLOAT128 FltS1;
#     FLOAT128 FltS2;
#     FLOAT128 FltS3;
#     FLOAT128 FltT0;
#     FLOAT128 FltT1;
#     FLOAT128 FltT2;
#     FLOAT128 FltT3;
#     FLOAT128 FltT4;
#     FLOAT128 FltT5;
#     FLOAT128 FltT6;
#     FLOAT128 FltT7;
#     FLOAT128 FltT8;
#     FLOAT128 FltT9;
#
#     //
#     // This section is specified/returned if the ContextFlags word contains
#     // the flag CONTEXT_HIGHER_FLOATING_POINT.
#     //
#
#     FLOAT128 FltS4;
#     FLOAT128 FltS5;
#     FLOAT128 FltS6;
#     FLOAT128 FltS7;
#     FLOAT128 FltS8;
#     FLOAT128 FltS9;
#     FLOAT128 FltS10;
#     FLOAT128 FltS11;
#     FLOAT128 FltS12;
#     FLOAT128 FltS13;
#     FLOAT128 FltS14;
#     FLOAT128 FltS15;
#     FLOAT128 FltS16;
#     FLOAT128 FltS17;
#     FLOAT128 FltS18;
#     FLOAT128 FltS19;
#
#     FLOAT128 FltF32;
#     FLOAT128 FltF33;
#     FLOAT128 FltF34;
#     FLOAT128 FltF35;
#     FLOAT128 FltF36;
#     FLOAT128 FltF37;
#     FLOAT128 FltF38;
#     FLOAT128 FltF39;
#
#     FLOAT128 FltF40;
#     FLOAT128 FltF41;
#     FLOAT128 FltF42;
#     FLOAT128 FltF43;
#     FLOAT128 FltF44;
#     FLOAT128 FltF45;
#     FLOAT128 FltF46;
#     FLOAT128 FltF47;
#     FLOAT128 FltF48;
#     FLOAT128 FltF49;
#
#     FLOAT128 FltF50;
#     FLOAT128 FltF51;
#     FLOAT128 FltF52;
#     FLOAT128 FltF53;
#     FLOAT128 FltF54;
#     FLOAT128 FltF55;
#     FLOAT128 FltF56;
#     FLOAT128 FltF57;
#     FLOAT128 FltF58;
#     FLOAT128 FltF59;
#
#     FLOAT128 FltF60;
#     FLOAT128 FltF61;
#     FLOAT128 FltF62;
#     FLOAT128 FltF63;
#     FLOAT128 FltF64;
#     FLOAT128 FltF65;
#     FLOAT128 FltF66;
#     FLOAT128 FltF67;
#     FLOAT128 FltF68;
#     FLOAT128 FltF69;
#
#     FLOAT128 FltF70;
#     FLOAT128 FltF71;
#     FLOAT128 FltF72;
#     FLOAT128 FltF73;
#     FLOAT128 FltF74;
#     FLOAT128 FltF75;
#     FLOAT128 FltF76;
#     FLOAT128 FltF77;
#     FLOAT128 FltF78;
#     FLOAT128 FltF79;
#
#     FLOAT128 FltF80;
#     FLOAT128 FltF81;
#     FLOAT128 FltF82;
#     FLOAT128 FltF83;
#     FLOAT128 FltF84;
#     FLOAT128 FltF85;
#     FLOAT128 FltF86;
#     FLOAT128 FltF87;
#     FLOAT128 FltF88;
#     FLOAT128 FltF89;
#
#     FLOAT128 FltF90;
#     FLOAT128 FltF91;
#     FLOAT128 FltF92;
#     FLOAT128 FltF93;
#     FLOAT128 FltF94;
#     FLOAT128 FltF95;
#     FLOAT128 FltF96;
#     FLOAT128 FltF97;
#     FLOAT128 FltF98;
#     FLOAT128 FltF99;
#
#     FLOAT128 FltF100;
#     FLOAT128 FltF101;
#     FLOAT128 FltF102;
#     FLOAT128 FltF103;
#     FLOAT128 FltF104;
#     FLOAT128 FltF105;
#     FLOAT128 FltF106;
#     FLOAT128 FltF107;
#     FLOAT128 FltF108;
#     FLOAT128 FltF109;
#
#     FLOAT128 FltF110;
#     FLOAT128 FltF111;
#     FLOAT128 FltF112;
#     FLOAT128 FltF113;
#     FLOAT128 FltF114;
#     FLOAT128 FltF115;
#     FLOAT128 FltF116;
#     FLOAT128 FltF117;
#     FLOAT128 FltF118;
#     FLOAT128 FltF119;
#
#     FLOAT128 FltF120;
#     FLOAT128 FltF121;
#     FLOAT128 FltF122;
#     FLOAT128 FltF123;
#     FLOAT128 FltF124;
#     FLOAT128 FltF125;
#     FLOAT128 FltF126;
#     FLOAT128 FltF127;
#
#     //
#     // This section is specified/returned if the ContextFlags word contains
#     // the flag CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT | CONTEXT_CONTROL.
#     //
#
#     ULONGLONG StFPSR;       //  FP status
#
#     //
#     // This section is specified/returned if the ContextFlags word contains
#     // the flag CONTEXT_INTEGER.
#     //
#     // N.B. The registers gp, sp, rp are part of the control context
#     //
#
#     ULONGLONG IntGp;        //  r1, volatile
#     ULONGLONG IntT0;        //  r2-r3, volatile
#     ULONGLONG IntT1;        //
#     ULONGLONG IntS0;        //  r4-r7, preserved
#     ULONGLONG IntS1;
#     ULONGLONG IntS2;
#     ULONGLONG IntS3;
#     ULONGLONG IntV0;        //  r8, volatile
#     ULONGLONG IntT2;        //  r9-r11, volatile
#     ULONGLONG IntT3;
#     ULONGLONG IntT4;
#     ULONGLONG IntSp;        //  stack pointer (r12), special
#     ULONGLONG IntTeb;       //  teb (r13), special
#     ULONGLONG IntT5;        //  r14-r31, volatile
#     ULONGLONG IntT6;
#     ULONGLONG IntT7;
#     ULONGLONG IntT8;
#     ULONGLONG IntT9;
#     ULONGLONG IntT10;
#     ULONGLONG IntT11;
#     ULONGLONG IntT12;
#     ULONGLONG IntT13;
#     ULONGLONG IntT14;
#     ULONGLONG IntT15;
#     ULONGLONG IntT16;
#     ULONGLONG IntT17;
#     ULONGLONG IntT18;
#     ULONGLONG IntT19;
#     ULONGLONG IntT20;
#     ULONGLONG IntT21;
#     ULONGLONG IntT22;
#
#     ULONGLONG IntNats;      //  Nat bits for r1-r31
#                             //  r1-r31 in bits 1 thru 31.
#     ULONGLONG Preds;        //  predicates, preserved
#
#     ULONGLONG BrRp;         //  return pointer, b0, preserved
#     ULONGLONG BrS0;         //  b1-b5, preserved
#     ULONGLONG BrS1;
#     ULONGLONG BrS2;
#     ULONGLONG BrS3;
#     ULONGLONG BrS4;
#     ULONGLONG BrT0;         //  b6-b7, volatile
#     ULONGLONG BrT1;
#
#     //
#     // This section is specified/returned if the ContextFlags word contains
#     // the flag CONTEXT_CONTROL.
#     //
#
#     // Other application registers
#     ULONGLONG ApUNAT;       //  User Nat collection register, preserved
#     ULONGLONG ApLC;         //  Loop counter register, preserved
#     ULONGLONG ApEC;         //  Epilog counter register, preserved
#     ULONGLONG ApCCV;        //  CMPXCHG value register, volatile
#     ULONGLONG ApDCR;        //  Default control register (TBD)
#
#     // Register stack info
#     ULONGLONG RsPFS;        //  Previous function state, preserved
#     ULONGLONG RsBSP;        //  Backing store pointer, preserved
#     ULONGLONG RsBSPSTORE;
#     ULONGLONG RsRSC;        //  RSE configuration, volatile
#     ULONGLONG RsRNAT;       //  RSE Nat collection register, preserved
#
#     // Trap Status Information
#     ULONGLONG StIPSR;       //  Interruption Processor Status
#     ULONGLONG StIIP;        //  Interruption IP
#     ULONGLONG StIFS;        //  Interruption Function State
#
#     // iA32 related control registers
#     ULONGLONG StFCR;        //  copy of Ar21
#     ULONGLONG Eflag;        //  Eflag copy of Ar24
#     ULONGLONG SegCSD;       //  iA32 CSDescriptor (Ar25)
#     ULONGLONG SegSSD;       //  iA32 SSDescriptor (Ar26)
#     ULONGLONG Cflag;        //  Cr0+Cr4 copy of Ar27
#     ULONGLONG StFSR;        //  x86 FP status (copy of AR28)
#     ULONGLONG StFIR;        //  x86 FP status (copy of AR29)
#     ULONGLONG StFDR;        //  x86 FP status (copy of AR30)
#
#       ULONGLONG UNUSEDPACK;   //  added to pack StFDR to 16-bytes
#
# } CONTEXT, *PCONTEXT;

class CONTEXT(Structure):
    arch = 'ia64'

    _pack_ = 16
    _fields_ = [
        ('ContextFlags',            DWORD),
        ('Fill1',                   DWORD * 3),     # alignment

        # CONTEXT_DEBUG
        ('DbI0',                    ULONGLONG),
        ('DbI1',                    ULONGLONG),
        ('DbI2',                    ULONGLONG),
        ('DbI3',                    ULONGLONG),
        ('DbI4',                    ULONGLONG),
        ('DbI5',                    ULONGLONG),
        ('DbI6',                    ULONGLONG),
        ('DbI7',                    ULONGLONG),
        ('DbD0',                    ULONGLONG),
        ('DbD1',                    ULONGLONG),
        ('DbD2',                    ULONGLONG),
        ('DbD3',                    ULONGLONG),
        ('DbD4',                    ULONGLONG),
        ('DbD5',                    ULONGLONG),
        ('DbD6',                    ULONGLONG),
        ('DbD7',                    ULONGLONG),

        # CONTEXT_LOWER_FLOATING_POINT
        ('FltS0',                   FLOAT128),
        ('FltS1',                   FLOAT128),
        ('FltS2',                   FLOAT128),
        ('FltS3',                   FLOAT128),
        ('FltT0',                   FLOAT128),
        ('FltT1',                   FLOAT128),
        ('FltT2',                   FLOAT128),
        ('FltT3',                   FLOAT128),
        ('FltT4',                   FLOAT128),
        ('FltT5',                   FLOAT128),
        ('FltT6',                   FLOAT128),
        ('FltT7',                   FLOAT128),
        ('FltT8',                   FLOAT128),
        ('FltT9',                   FLOAT128),

        # CONTEXT_HIGHER_FLOATING_POINT
        ('FltS4',                   FLOAT128),
        ('FltS5',                   FLOAT128),
        ('FltS6',                   FLOAT128),
        ('FltS7',                   FLOAT128),
        ('FltS8',                   FLOAT128),
        ('FltS9',                   FLOAT128),
        ('FltS10',                  FLOAT128),
        ('FltS11',                  FLOAT128),
        ('FltS12',                  FLOAT128),
        ('FltS13',                  FLOAT128),
        ('FltS14',                  FLOAT128),
        ('FltS15',                  FLOAT128),
        ('FltS16',                  FLOAT128),
        ('FltS17',                  FLOAT128),
        ('FltS18',                  FLOAT128),
        ('FltS19',                  FLOAT128),
        ('FltF32',                  FLOAT128),
        ('FltF33',                  FLOAT128),
        ('FltF34',                  FLOAT128),
        ('FltF35',                  FLOAT128),
        ('FltF36',                  FLOAT128),
        ('FltF37',                  FLOAT128),
        ('FltF38',                  FLOAT128),
        ('FltF39',                  FLOAT128),
        ('FltF40',                  FLOAT128),
        ('FltF41',                  FLOAT128),
        ('FltF42',                  FLOAT128),
        ('FltF43',                  FLOAT128),
        ('FltF44',                  FLOAT128),
        ('FltF45',                  FLOAT128),
        ('FltF46',                  FLOAT128),
        ('FltF47',                  FLOAT128),
        ('FltF48',                  FLOAT128),
        ('FltF49',                  FLOAT128),
        ('FltF50',                  FLOAT128),
        ('FltF51',                  FLOAT128),
        ('FltF52',                  FLOAT128),
        ('FltF53',                  FLOAT128),
        ('FltF54',                  FLOAT128),
        ('FltF55',                  FLOAT128),
        ('FltF56',                  FLOAT128),
        ('FltF57',                  FLOAT128),
        ('FltF58',                  FLOAT128),
        ('FltF59',                  FLOAT128),
        ('FltF60',                  FLOAT128),
        ('FltF61',                  FLOAT128),
        ('FltF62',                  FLOAT128),
        ('FltF63',                  FLOAT128),
        ('FltF64',                  FLOAT128),
        ('FltF65',                  FLOAT128),
        ('FltF66',                  FLOAT128),
        ('FltF67',                  FLOAT128),
        ('FltF68',                  FLOAT128),
        ('FltF69',                  FLOAT128),
        ('FltF70',                  FLOAT128),
        ('FltF71',                  FLOAT128),
        ('FltF72',                  FLOAT128),
        ('FltF73',                  FLOAT128),
        ('FltF74',                  FLOAT128),
        ('FltF75',                  FLOAT128),
        ('FltF76',                  FLOAT128),
        ('FltF77',                  FLOAT128),
        ('FltF78',                  FLOAT128),
        ('FltF79',                  FLOAT128),
        ('FltF80',                  FLOAT128),
        ('FltF81',                  FLOAT128),
        ('FltF82',                  FLOAT128),
        ('FltF83',                  FLOAT128),
        ('FltF84',                  FLOAT128),
        ('FltF85',                  FLOAT128),
        ('FltF86',                  FLOAT128),
        ('FltF87',                  FLOAT128),
        ('FltF88',                  FLOAT128),
        ('FltF89',                  FLOAT128),
        ('FltF90',                  FLOAT128),
        ('FltF91',                  FLOAT128),
        ('FltF92',                  FLOAT128),
        ('FltF93',                  FLOAT128),
        ('FltF94',                  FLOAT128),
        ('FltF95',                  FLOAT128),
        ('FltF96',                  FLOAT128),
        ('FltF97',                  FLOAT128),
        ('FltF98',                  FLOAT128),
        ('FltF99',                  FLOAT128),
        ('FltF100',                 FLOAT128),
        ('FltF101',                 FLOAT128),
        ('FltF102',                 FLOAT128),
        ('FltF103',                 FLOAT128),
        ('FltF104',                 FLOAT128),
        ('FltF105',                 FLOAT128),
        ('FltF106',                 FLOAT128),
        ('FltF107',                 FLOAT128),
        ('FltF108',                 FLOAT128),
        ('FltF109',                 FLOAT128),
        ('FltF110',                 FLOAT128),
        ('FltF111',                 FLOAT128),
        ('FltF112',                 FLOAT128),
        ('FltF113',                 FLOAT128),
        ('FltF114',                 FLOAT128),
        ('FltF115',                 FLOAT128),
        ('FltF116',                 FLOAT128),
        ('FltF117',                 FLOAT128),
        ('FltF118',                 FLOAT128),
        ('FltF119',                 FLOAT128),
        ('FltF120',                 FLOAT128),
        ('FltF121',                 FLOAT128),
        ('FltF122',                 FLOAT128),
        ('FltF123',                 FLOAT128),
        ('FltF124',                 FLOAT128),
        ('FltF125',                 FLOAT128),
        ('FltF126',                 FLOAT128),
        ('FltF127',                 FLOAT128),

        # CONTEXT_LOWER_FLOATING_POINT | CONTEXT_HIGHER_FLOATING_POINT | CONTEXT_CONTROL
        ('StFPSR',                  ULONGLONG),

        # CONTEXT_INTEGER (except gp, sp, rp)
        ('IntGp',                   ULONGLONG), # r1, volatile
        ('IntT0',                   ULONGLONG), # r2-r3, volatile
        ('IntT1',                   ULONGLONG),
        ('IntS0',                   ULONGLONG), # r4-r7, preserved
        ('IntS1',                   ULONGLONG),
        ('IntS2',                   ULONGLONG),
        ('IntS3',                   ULONGLONG),
        ('IntV0',                   ULONGLONG), # r8, volatile
        ('IntT2',                   ULONGLONG), # r9-r11, volatile
        ('IntT3',                   ULONGLONG),
        ('IntT4',                   ULONGLONG),
        ('IntSp',                   ULONGLONG), # stack pointer (r12), special
        ('IntTeb',                  ULONGLONG), # teb (r13), special
        ('IntT5',                   ULONGLONG), # r14-r31, volatile
        ('IntT6',                   ULONGLONG),
        ('IntT7',                   ULONGLONG),
        ('IntT8',                   ULONGLONG),
        ('IntT9',                   ULONGLONG),
        ('IntT10',                  ULONGLONG),
        ('IntT11',                  ULONGLONG),
        ('IntT12',                  ULONGLONG),
        ('IntT13',                  ULONGLONG),
        ('IntT14',                  ULONGLONG),
        ('IntT15',                  ULONGLONG),
        ('IntT16',                  ULONGLONG),
        ('IntT17',                  ULONGLONG),
        ('IntT18',                  ULONGLONG),
        ('IntT19',                  ULONGLONG),
        ('IntT20',                  ULONGLONG),
        ('IntT21',                  ULONGLONG),
        ('IntT22',                  ULONGLONG),
        ('IntNats',                 ULONGLONG), # Nat bits for r1-r31
                                                # r1-r31 in bits 1 thru 31.
        ('Preds',                   ULONGLONG), # predicates, preserved

        ('BrRp',                    ULONGLONG), # return pointer, b0, preserved
        ('BrS0',                    ULONGLONG), # b1-b5, preserved
        ('BrS1',                    ULONGLONG),
        ('BrS2',                    ULONGLONG),
        ('BrS3',                    ULONGLONG),
        ('BrS4',                    ULONGLONG),
        ('BrT0',                    ULONGLONG), # b6-b7, volatile
        ('BrT1',                    ULONGLONG),

        # CONTEXT_CONTROL

        # Other application registers
        ('ApUNAT',                  ULONGLONG), # User Nat collection register, preserved
        ('ApLC',                    ULONGLONG), # Loop counter register, preserved
        ('ApEC',                    ULONGLONG), # Epilog counter register, preserved
        ('ApCCV',                   ULONGLONG), # CMPXCHG value register, volatile
        ('ApDCR',                   ULONGLONG), # Default control register (TBD)

        # Register stack info
        ('RsPFS',                   ULONGLONG), # Previous function state, preserved
        ('RsBSP',                   ULONGLONG), # Backing store pointer, preserved
        ('RsBSPSTORE',              ULONGLONG),
        ('RsRSC',                   ULONGLONG), # RSE configuration, volatile
        ('RsRNAT',                  ULONGLONG), # RSE Nat collection register, preserved

        # Trap Status Information
        ('StIPSR',                  ULONGLONG), # Interruption Processor Status
        ('StIIP',                   ULONGLONG), # Interruption IP
        ('StIFS',                   ULONGLONG), # Interruption Function State

        # iA32 related control registers
        ('StFCR',                   ULONGLONG), # copy of Ar21
        ('Eflag',                   ULONGLONG), # Eflag copy of Ar24
        ('SegCSD',                  ULONGLONG), # iA32 CSDescriptor (Ar25)
        ('SegSSD',                  ULONGLONG), # iA32 SSDescriptor (Ar26)
        ('Cflag',                   ULONGLONG), # Cr0+Cr4 copy of Ar27
        ('StFSR',                   ULONGLONG), # x86 FP status (copy of AR28)
        ('StFIR',                   ULONGLONG), # x86 FP status (copy of AR29)
        ('StFDR',                   ULONGLONG), # x86 FP status (copy of AR30)
        ('UNUSEDPACK',              ULONGLONG), # added to pack StFDR to 16-bytes
    ]

PCONTEXT = POINTER(CONTEXT)
LPCONTEXT = PCONTEXT

class Context(dict):
    """
    Register context dictionary for the %s architecture.
    """ % CONTEXT.arch
    arch = CONTEXT.arch

    # See http://msdn.microsoft.com/en-us/library/cc266544.aspx

    def __get_gp(self):
        return self['IntGp']
    def __set_gp(self, value):
        self['IntGp'] = value
    gp = property(__get_gp, __set_gp)

    def __get_sp(self):
        return self['IntSp']
    def __set_sp(self, value):
        self['IntSp'] = value
    sp = property(__get_sp, __set_sp)

    def __get_rp(self):
        return self['IntRp']
    def __set_rp(self, value):
        self['IntRp'] = value
    rp = property(__get_rp, __set_rp)

###############################################################################

# BOOL WINAPI GetThreadContext(
#   __in     HANDLE hThread,
#   __inout  LPCONTEXT lpContext
# );
def GetThreadContext(hThread, ContextFlags = None):
    _GetThreadContext = windll.kernel32.GetThreadContext
    _GetThreadContext.argtypes = [HANDLE, LPCONTEXT]
    _GetThreadContext.restype = bool
    _GetThreadContext.errcheck = RaiseIfZero

    if ContextFlags is None:
        ContextFlags = CONTEXT_ALL
    lpContext = CONTEXT()
    lpContext.ContextFlags = ContextFlags
    _GetThreadContext(hThread, ctypes.byref(lpContext))
    return lpContext.to_dict()

# BOOL WINAPI SetThreadContext(
#   __in  HANDLE hThread,
#   __in  const CONTEXT* lpContext
# );
def SetThreadContext(hThread, lpContext):
    _SetThreadContext = windll.kernel32.SetThreadContext
    _SetThreadContext.argtypes = [HANDLE, LPCONTEXT]
    _SetThreadContext.restype = bool
    _SetThreadContext.errcheck = RaiseIfZero

    if isinstance(lpContext, dict):
        lpContext = CONTEXT.from_dict(lpContext)
    _SetThreadContext(hThread, ctypes.byref(lpContext))
