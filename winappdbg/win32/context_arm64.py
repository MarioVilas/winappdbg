#!/usr/bin/env python
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
ARM64 processor context structures and functions.
"""

from .defines import (
    BYTE,
    DWORD,
    DWORD64,
    HANDLE,
    POINTER,
    WORD,
    ULONGLONG,
    LONGLONG,
    RaiseIfZero,
    Structure,
    Union,
    byref,
    windll,
)
from .version import ARCH_ARM64

# ==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
# ==============================================================================

# --- Exception information types -----------------------------------------------

EXCEPTION_READ_FAULT = 0       # exception caused by a read
EXCEPTION_WRITE_FAULT = 1      # exception caused by a write
EXCEPTION_EXECUTE_FAULT = 8    # exception caused by an instruction fetch

# --- CONTEXT structures and constants -----------------------------------------

CONTEXT_ARM64 = 0x00400000

CONTEXT_CONTROL = CONTEXT_ARM64 | 0x1
CONTEXT_INTEGER = CONTEXT_ARM64 | 0x2
CONTEXT_FLOATING_POINT = CONTEXT_ARM64 | 0x4
CONTEXT_DEBUG_REGISTERS = CONTEXT_ARM64 | 0x8
CONTEXT_X18 = CONTEXT_ARM64 | 0x10
CONTEXT_XSTATE = CONTEXT_ARM64 | 0x20

CONTEXT_FULL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT
CONTEXT_ALL = (
    CONTEXT_CONTROL
    | CONTEXT_INTEGER
    | CONTEXT_FLOATING_POINT
    | CONTEXT_DEBUG_REGISTERS
    | CONTEXT_X18
)

ARM64_MAX_BREAKPOINTS = 8
ARM64_MAX_WATCHPOINTS = 2

# typedef union _ARM64_NT_NEON128 {
#     struct {
#         ULONGLONG Low;
#         LONGLONG High;
#     } DUMMYSTRUCTNAME;
#     double D[2];
#     float S[4];
#     WORD   H[8];
#     BYTE  B[16];
# } ARM64_NT_NEON128, *PARM64_NT_NEON128;
class _ARM64_NT_NEON128_STRUCT(Structure):
    _fields_ = [
        ("Low", ULONGLONG),
        ("High", LONGLONG),
    ]

class ARM64_NT_NEON128(Union):
    _fields_ = [
        ("s", _ARM64_NT_NEON128_STRUCT),
        ("D", 2 * DWORD64),                 # XXX FIXME should be 64-bit floating point instead of DWORD64
        ("S", 4 * DWORD),                   # XXX FIXME should be 32-bit floating point instead of DWORD
        ("H", 8 * WORD),
        ("B", 16 * BYTE),
    ]

NEON128 = ARM64_NT_NEON128
PNEON128 = POINTER(NEON128)
PARM64_NT_NEON128 = PNEON128

# typedef struct DECLSPEC_ALIGN(16) DECLSPEC_NOINITALL _ARM64_NT_CONTEXT {
#     DWORD ContextFlags;
#     DWORD Cpsr;       // NZVF + DAIF + CurrentEL + SPSel
#     union {
#         struct {
#             DWORD64 X0;
#             ...
#             DWORD64 X28;
#             DWORD64 Fp;
#             DWORD64 Lr;
#         } DUMMYSTRUCTNAME;
#         DWORD64 X[31];
#     } DUMMYUNIONNAME;
#     DWORD64 Sp;
#     DWORD64 Pc;
#     ARM64_NT_NEON128 V[32];
#     DWORD Fpcr;
#     DWORD Fpsr;
#     DWORD Bcr[ARM64_MAX_BREAKPOINTS];
#     DWORD64 Bvr[ARM64_MAX_BREAKPOINTS];
#     DWORD Wcr[ARM64_MAX_WATCHPOINTS];
#     DWORD64 Wvr[ARM64_MAX_WATCHPOINTS];
# } ARM64_NT_CONTEXT, *PARM64_NT_CONTEXT;
class _CONTEXT_REGS_STRUCT(Structure):
    _fields_ = [
        ("X0", DWORD64), ("X1", DWORD64), ("X2", DWORD64),
        ("X3", DWORD64), ("X4", DWORD64), ("X5", DWORD64),
        ("X6", DWORD64), ("X7", DWORD64), ("X8", DWORD64),
        ("X9", DWORD64), ("X10", DWORD64), ("X11", DWORD64),
        ("X12", DWORD64), ("X13", DWORD64), ("X14", DWORD64),
        ("X15", DWORD64), ("X16", DWORD64), ("X17", DWORD64),
        ("X18", DWORD64), ("X19", DWORD64), ("X20", DWORD64),
        ("X21", DWORD64), ("X22", DWORD64), ("X23", DWORD64),
        ("X24", DWORD64), ("X25", DWORD64), ("X26", DWORD64),
        ("X27", DWORD64), ("X28", DWORD64),
        ("Fp", DWORD64),
        ("Lr", DWORD64),
    ]

class _CONTEXT_REGS_UNION(Union):
    _fields_ = [
        ("s", _CONTEXT_REGS_STRUCT),
        ("X", 31 * DWORD64),
    ]

class CONTEXT(Structure):
    arch = ARCH_ARM64
    _pack_ = 16
    _fields_ = [
        ("ContextFlags", DWORD),
        ("Cpsr", DWORD),
        ("Regs", _CONTEXT_REGS_UNION),
        ("Sp", DWORD64),
        ("Pc", DWORD64),
        ("V", ARM64_NT_NEON128 * 32),
        ("Fpcr", DWORD),
        ("Fpsr", DWORD),
        ("Bcr", DWORD * ARM64_MAX_BREAKPOINTS),
        ("Bvr", DWORD64 * ARM64_MAX_BREAKPOINTS),
        ("Wcr", DWORD * ARM64_MAX_WATCHPOINTS),
        ("Wvr", DWORD64 * ARM64_MAX_WATCHPOINTS),
    ]

    def to_dict(self):
        ctx = Context()
        ctx["ContextFlags"] = self.ContextFlags
        if (self.ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            ctx["Fp"] = self.Regs.s.Fp
            ctx["Lr"] = self.Regs.s.Lr
            ctx["Sp"] = self.Sp
            ctx["Pc"] = self.Pc
            ctx["Cpsr"] = self.Cpsr
        if (self.ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for i in range(29):
                ctx[f"X{i}"] = self.Regs.X[i]
        if (self.ContextFlags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT:
            ctx["Fpcr"] = self.Fpcr
            ctx["Fpsr"] = self.Fpsr
            # V registers would go here
        if (self.ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            ctx["Bcr"] = list(self.Bcr)
            ctx["Bvr"] = list(self.Bvr)
            ctx["Wcr"] = list(self.Wcr)
            ctx["Wvr"] = list(self.Wvr)
        return ctx

PCONTEXT = POINTER(CONTEXT)
LPCONTEXT = PCONTEXT

class Context(dict):
    arch = CONTEXT.arch

    def __get_pc(self):
        return self["Pc"]

    def __set_pc(self, value):
        self["Pc"] = value

    pc = property(__get_pc, __set_pc)

    def __get_sp(self):
        return self["Sp"]

    def __set_sp(self, value):
        self["Sp"] = value

    sp = property(__get_sp, __set_sp)

    def __get_fp(self):
        return self["Fp"]

    def __set_fp(self, value):
        self["Fp"] = value

    fp = property(__get_fp, __set_fp)


# BOOL WINAPI GetThreadContext(
#   __in     HANDLE hThread,
#   __inout  LPCONTEXT lpContext
# );
def GetThreadContext(hThread, ContextFlags=None, raw=False):
    _GetThreadContext = windll.kernel32.GetThreadContext
    _GetThreadContext.argtypes = [HANDLE, LPCONTEXT]
    _GetThreadContext.restype = bool
    _GetThreadContext.errcheck = RaiseIfZero

    if ContextFlags is None:
        ContextFlags = CONTEXT_ALL
    Context = CONTEXT()
    Context.ContextFlags = ContextFlags
    _GetThreadContext(hThread, byref(Context))
    if raw:
        return Context
    return Context.to_dict()


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
        ctx = CONTEXT()
        ctx.ContextFlags = lpContext["ContextFlags"]
        if (ctx.ContextFlags & CONTEXT_CONTROL) == CONTEXT_CONTROL:
            ctx.Regs.s.Fp = lpContext["Fp"]
            ctx.Regs.s.Lr = lpContext["Lr"]
            ctx.Sp = lpContext["Sp"]
            ctx.Pc = lpContext["Pc"]
            ctx.Cpsr = lpContext["Cpsr"]
        if (ctx.ContextFlags & CONTEXT_INTEGER) == CONTEXT_INTEGER:
            for i in range(29):
                ctx.Regs.X[i] = lpContext[f"X{i}"]
        if (ctx.ContextFlags & CONTEXT_DEBUG_REGISTERS) == CONTEXT_DEBUG_REGISTERS:
            bcr = lpContext.get("Bcr")
            if bcr:
                for i, v in enumerate(bcr):
                    ctx.Bcr[i] = v
            bvr = lpContext.get("Bvr")
            if bvr:
                for i, v in enumerate(bvr):
                    ctx.Bvr[i] = v
            wcr = lpContext.get("Wcr")
            if wcr:
                for i, v in enumerate(wcr):
                    ctx.Wcr[i] = v
            wvr = lpContext.get("Wvr")
            if wvr:
                for i, v in enumerate(wvr):
                    ctx.Wvr[i] = v
        lpContext = ctx
    _SetThreadContext(hThread, byref(lpContext))

# ==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith("_")]
__all__.sort()
# ==============================================================================