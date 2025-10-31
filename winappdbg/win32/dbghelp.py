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
Wrapper for dbghelp.dll in ctypes.
"""

import ctypes

from .defines import (
    BOOL,
    CHAR,
    DWORD,
    DWORD64,
    ERROR_SUCCESS,
    GUID,
    HANDLE,
    HRESULT,
    HWND,
    LPDWORD,
    LPSTR,
    LPVOID,
    LPWSTR,
    MAX_PATH,
    NULL,
    PDWORD,
    PDWORD64,
    POINTER,
    PSTR,
    PVOID,
    SIZE_T,
    ULONG,
    ULONG32,
    ULONG64,
    ULONG_PTR,
    Union,
    USHORT,
    WCHAR,
    WINFUNCTYPE,
    WORD,
    GuessStringType,
    MakeWideVersion,
    RaiseIfZero,
    Structure,
    byref,
    sizeof,
    windll,
)
from .kernel32 import GetLastError, SetLastError
from .version import VS_FIXEDFILEINFO

# DbgHelp versions and features list:
# http://msdn.microsoft.com/en-us/library/windows/desktop/ms679294(v=vs.85).aspx

# ==============================================================================
# This is used later on to calculate the list of exported symbols.
_all = None
_all = set(vars().keys())
# ==============================================================================

# SymGetHomeDirectory "type" values
hdBase = 0
hdSym = 1
hdSrc = 2

UNDNAME_32_BIT_DECODE = 0x0800
UNDNAME_COMPLETE = 0x0000
UNDNAME_NAME_ONLY = 0x1000
UNDNAME_NO_ACCESS_SPECIFIERS = 0x0080
UNDNAME_NO_ALLOCATION_LANGUAGE = 0x0010
UNDNAME_NO_ALLOCATION_MODEL = 0x0008
UNDNAME_NO_ARGUMENTS = 0x2000
UNDNAME_NO_CV_THISTYPE = 0x0040
UNDNAME_NO_FUNCTION_RETURNS = 0x0004
UNDNAME_NO_LEADING_UNDERSCORES = 0x0001
UNDNAME_NO_MEMBER_TYPE = 0x0200
UNDNAME_NO_MS_KEYWORDS = 0x0002
UNDNAME_NO_MS_THISTYPE = 0x0020
UNDNAME_NO_RETURN_UDT_MODEL = 0x0400
UNDNAME_NO_SPECIAL_SYMS = 0x4000
UNDNAME_NO_THISTYPE = 0x0060
UNDNAME_NO_THROW_SIGNATURES = 0x0100

# --- IMAGEHLP_MODULE structure and related ------------------------------------

SYMOPT_ALLOW_ABSOLUTE_SYMBOLS = 0x00000800
SYMOPT_ALLOW_ZERO_ADDRESS = 0x01000000
SYMOPT_AUTO_PUBLICS = 0x00010000
SYMOPT_CASE_INSENSITIVE = 0x00000001
SYMOPT_DEBUG = 0x80000000
SYMOPT_DEFERRED_LOADS = 0x00000004
SYMOPT_DISABLE_SYMSRV_AUTODETECT = 0x02000000
SYMOPT_EXACT_SYMBOLS = 0x00000400
SYMOPT_FAIL_CRITICAL_ERRORS = 0x00000200
SYMOPT_FAVOR_COMPRESSED = 0x00800000
SYMOPT_FLAT_DIRECTORY = 0x00400000
SYMOPT_IGNORE_CVREC = 0x00000080
SYMOPT_IGNORE_IMAGEDIR = 0x00200000
SYMOPT_IGNORE_NT_SYMPATH = 0x00001000
SYMOPT_INCLUDE_32BIT_MODULES = 0x00002000
SYMOPT_LOAD_ANYTHING = 0x00000040
SYMOPT_LOAD_LINES = 0x00000010
SYMOPT_NO_CPP = 0x00000008
SYMOPT_NO_IMAGE_SEARCH = 0x00020000
SYMOPT_NO_PROMPTS = 0x00080000
SYMOPT_NO_PUBLICS = 0x00008000
SYMOPT_NO_UNQUALIFIED_LOADS = 0x00000100
SYMOPT_OVERWRITE = 0x00100000
SYMOPT_PUBLICS_ONLY = 0x00004000
SYMOPT_SECURE = 0x00040000
SYMOPT_UNDNAME = 0x00000002

##SSRVOPT_DWORD
##SSRVOPT_DWORDPTR
##SSRVOPT_GUIDPTR
##
##SSRVOPT_CALLBACK
##SSRVOPT_DOWNSTREAM_STORE
##SSRVOPT_FLAT_DEFAULT_STORE
##SSRVOPT_FAVOR_COMPRESSED
##SSRVOPT_NOCOPY
##SSRVOPT_OVERWRITE
##SSRVOPT_PARAMTYPE
##SSRVOPT_PARENTWIN
##SSRVOPT_PROXY
##SSRVOPT_RESET
##SSRVOPT_SECURE
##SSRVOPT_SETCONTEXT
##SSRVOPT_TRACE
##SSRVOPT_UNATTENDED

#    typedef enum
#    {
#        SymNone = 0,
#        SymCoff,
#        SymCv,
#        SymPdb,
#        SymExport,
#        SymDeferred,
#        SymSym,
#        SymDia,
#        SymVirtual,
#        NumSymTypes
#    } SYM_TYPE;
SymNone = 0
SymCoff = 1
SymCv = 2
SymPdb = 3
SymExport = 4
SymDeferred = 5
SymSym = 6
SymDia = 7
SymVirtual = 8
NumSymTypes = 9

#    typedef struct _IMAGEHLP_MODULE64 {
#      DWORD    SizeOfStruct;
#      DWORD64  BaseOfImage;
#      DWORD    ImageSize;
#      DWORD    TimeDateStamp;
#      DWORD    CheckSum;
#      DWORD    NumSyms;
#      SYM_TYPE SymType;
#      TCHAR    ModuleName[32];
#      TCHAR    ImageName[256];
#      TCHAR    LoadedImageName[256];
#      TCHAR    LoadedPdbName[256];
#      DWORD    CVSig;
#      TCHAR    CVData[MAX_PATH*3];
#      DWORD    PdbSig;
#      GUID     PdbSig70;
#      DWORD    PdbAge;
#      BOOL     PdbUnmatched;
#      BOOL     DbgUnmatched;
#      BOOL     LineNumbers;
#      BOOL     GlobalSymbols;
#      BOOL     TypeInfo;
#      BOOL     SourceIndexed;
#      BOOL     Publics;
#    } IMAGEHLP_MODULE64, *PIMAGEHLP_MODULE64;


class IMAGEHLP_MODULE(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD),
        ("ImageSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("CheckSum", DWORD),
        ("NumSyms", DWORD),
        ("SymType", DWORD),  # SYM_TYPE
        ("ModuleName", CHAR * 32),
        ("ImageName", CHAR * 256),
        ("LoadedImageName", CHAR * 256),
    ]


PIMAGEHLP_MODULE = POINTER(IMAGEHLP_MODULE)


class IMAGEHLP_MODULE64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD64),
        ("ImageSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("CheckSum", DWORD),
        ("NumSyms", DWORD),
        ("SymType", DWORD),  # SYM_TYPE
        ("ModuleName", CHAR * 32),
        ("ImageName", CHAR * 256),
        ("LoadedImageName", CHAR * 256),
        ("LoadedPdbName", CHAR * 256),
        ("CVSig", DWORD),
        ("CVData", CHAR * (MAX_PATH * 3)),
        ("PdbSig", DWORD),
        ("PdbSig70", GUID),
        ("PdbAge", DWORD),
        ("PdbUnmatched", BOOL),
        ("DbgUnmatched", BOOL),
        ("LineNumbers", BOOL),
        ("GlobalSymbols", BOOL),
        ("TypeInfo", BOOL),
        ("SourceIndexed", BOOL),
        ("Publics", BOOL),
    ]


PIMAGEHLP_MODULE64 = POINTER(IMAGEHLP_MODULE64)


class IMAGEHLP_MODULEW(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD),
        ("ImageSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("CheckSum", DWORD),
        ("NumSyms", DWORD),
        ("SymType", DWORD),  # SYM_TYPE
        ("ModuleName", WCHAR * 32),
        ("ImageName", WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
    ]


PIMAGEHLP_MODULEW = POINTER(IMAGEHLP_MODULEW)


class IMAGEHLP_MODULEW64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("BaseOfImage", DWORD64),
        ("ImageSize", DWORD),
        ("TimeDateStamp", DWORD),
        ("CheckSum", DWORD),
        ("NumSyms", DWORD),
        ("SymType", DWORD),  # SYM_TYPE
        ("ModuleName", WCHAR * 32),
        ("ImageName", WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
        ("LoadedPdbName", WCHAR * 256),
        ("CVSig", DWORD),
        ("CVData", WCHAR * (MAX_PATH * 3)),
        ("PdbSig", DWORD),
        ("PdbSig70", GUID),
        ("PdbAge", DWORD),
        ("PdbUnmatched", BOOL),
        ("DbgUnmatched", BOOL),
        ("LineNumbers", BOOL),
        ("GlobalSymbols", BOOL),
        ("TypeInfo", BOOL),
        ("SourceIndexed", BOOL),
        ("Publics", BOOL),
    ]


PIMAGEHLP_MODULEW64 = POINTER(IMAGEHLP_MODULEW64)

# typedef MINIDUMP_TYPE
MINIDUMP_TYPE = DWORD
MiniDumpNormal = 0x00000000
MiniDumpWithDataSegs = 0x00000001
MiniDumpWithFullMemory = 0x00000002
MiniDumpWithHandleData = 0x00000004
MiniDumpFilterMemory = 0x00000008
MiniDumpScanMemory = 0x00000010
MiniDumpWithUnloadedModules = 0x00000020
MiniDumpWithIndirectlyReferencedMemory = 0x00000040
MiniDumpFilterModulePaths = 0x00000080
MiniDumpWithProcessThreadData = 0x00000100
MiniDumpWithPrivateReadWriteMemory = 0x00000200
MiniDumpWithoutOptionalData = 0x00000400
MiniDumpWithFullMemoryInfo = 0x00000800
MiniDumpWithThreadInfo = 0x00001000
MiniDumpWithCodeSegs = 0x00002000
MiniDumpWithoutAuxiliaryState = 0x00004000
MiniDumpWithFullAuxiliaryState = 0x00008000
MiniDumpWithPrivateWriteCopyMemory = 0x00010000
MiniDumpIgnoreInaccessibleMemory = 0x00020000
MiniDumpWithTokenInformation = 0x00040000
MiniDumpWithModuleHeaders = 0x00080000
MiniDumpFilterTriage = 0x00100000
MiniDumpWithAvxXStateContext = 0x00200000
MiniDumpWithIptTrace = 0x00400000
MiniDumpScanInaccessiblePartialPages = 0x00800000
MiniDumpFilterWriteCombinedMemory = 0x01000000  # Value not specified in C, use next bit
MiniDumpValidTypeFlags = 0x01FFFFFF
MiniDumpNoIgnoreInaccessibleMemory = (
    0x02000000  # Value not specified in C, use next bit
)
MiniDumpValidTypeFlagsEx = 0x03FFFFFF  # Value not specified in C, use next bit

# MINIDUMP_CALLBACK_TYPE enumeration
ModuleCallback = 0
ThreadCallback = 1
ThreadExCallback = 2
IncludeThreadCallback = 3
IncludeModuleCallback = 4
MemoryCallback = 5
CancelCallback = 6
WriteKernelMinidumpCallback = 7
KernelMinidumpStatusCallback = 8
RemoveMemoryCallback = 9
IncludeVmRegionCallback = 10
IoStartCallback = 11
IoWriteAllCallback = 12
IoFinishCallback = 13
ReadMemoryFailureCallback = 14
SecondaryFlagsCallback = 15
IsProcessSnapshotCallback = 16
VmStartCallback = 17
VmQueryCallback = 18
VmPreReadCallback = 19
VmPostReadCallback = 20

PMINIDUMP_CALLBACK_TYPE = PDWORD

# MINIDUMP_SECONDARY_FLAGS enumeration
MiniSecondaryWithoutPowerInfo = 0x00000001
MiniSecondaryValidFlags = 0x00000001

PMINIDUMP_SECONDARY_FLAGS = PDWORD

# MODULE_WRITE_FLAGS enumeration
ModuleWriteModule = 0x0001
ModuleWriteDataSeg = 0x0002
ModuleWriteMiscRecord = 0x0004
ModuleWriteCvRecord = 0x0008
ModuleReferencedByMemory = 0x0010
ModuleWriteTlsData = 0x0020
ModuleWriteCodeSegs = 0x0040

PMODULE_WRITE_FLAGS = PDWORD

# THREAD_WRITE_FLAGS enumeration
ThreadWriteThread = 0x0001
ThreadWriteStack = 0x0002
ThreadWriteContext = 0x0004
ThreadWriteBackingStore = 0x0008
ThreadWriteInstructionWindow = 0x0010
ThreadWriteThreadData = 0x0020
ThreadWriteThreadInfo = 0x0040

PTHREAD_WRITE_FLAGS = PDWORD


# typedef struct _MINIDUMP_THREAD_CALLBACK {
#   ULONG   ThreadId;
#   HANDLE  ThreadHandle;
#   ULONG   Pad;
#   CONTEXT Context;
#   ULONG   SizeOfContext;
#   ULONG64 StackBase;
#   ULONG64 StackEnd;
# } MINIDUMP_THREAD_CALLBACK, *PMINIDUMP_THREAD_CALLBACK;
class MINIDUMP_THREAD_CALLBACK(Structure):
    _fields_ = [
        ("ThreadId", ULONG),
        ("ThreadHandle", HANDLE),
        ("Pad", ULONG),
        ("Context", PVOID),  # PCONTEXT (depends on target architecture)
        ("SizeOfContext", ULONG),
        ("StackBase", ULONG64),
        ("StackEnd", ULONG64),
    ]


PMINIDUMP_THREAD_CALLBACK = POINTER(MINIDUMP_THREAD_CALLBACK)


# typedef struct _MINIDUMP_THREAD_EX_CALLBACK {
#   ULONG   ThreadId;
#   HANDLE  ThreadHandle;
#   ULONG   Pad;
#   CONTEXT Context;
#   ULONG   SizeOfContext;
#   ULONG64 StackBase;
#   ULONG64 StackEnd;
#   ULONG64 BackingStoreBase;
#   ULONG64 BackingStoreEnd;
# } MINIDUMP_THREAD_EX_CALLBACK, *PMINIDUMP_THREAD_EX_CALLBACK;
class MINIDUMP_THREAD_EX_CALLBACK(Structure):
    _fields_ = [
        ("ThreadId", ULONG),
        ("ThreadHandle", HANDLE),
        ("Pad", ULONG),
        ("Context", PVOID),  # PCONTEXT (depends on target architecture)
        ("SizeOfContext", ULONG),
        ("StackBase", ULONG64),
        ("StackEnd", ULONG64),
        ("BackingStoreBase", ULONG64),
        ("BackingStoreEnd", ULONG64),
    ]


PMINIDUMP_THREAD_EX_CALLBACK = POINTER(MINIDUMP_THREAD_EX_CALLBACK)


# typedef struct _MINIDUMP_MODULE_CALLBACK {
#   PWCHAR                FullPath;
#   ULONG64               BaseOfImage;
#   ULONG                 SizeOfImage;
#   ULONG                 CheckSum;
#   ULONG                 TimeDateStamp;
#   VS_FIXEDFILEINFO      VersionInfo;
#   PVOID                 CvRecord;
#   ULONG                 SizeOfCvRecord;
#   PVOID                 MiscRecord;
#   ULONG                 SizeOfMiscRecord;
# } MINIDUMP_MODULE_CALLBACK, *PMINIDUMP_MODULE_CALLBACK;
class MINIDUMP_MODULE_CALLBACK(Structure):
    _fields_ = [
        ("FullPath", LPWSTR),
        ("BaseOfImage", ULONG64),
        ("SizeOfImage", ULONG),
        ("CheckSum", ULONG),
        ("TimeDateStamp", ULONG),
        ("VersionInfo", VS_FIXEDFILEINFO),
        ("CvRecord", PVOID),
        ("SizeOfCvRecord", ULONG),
        ("MiscRecord", PVOID),
        ("SizeOfMiscRecord", ULONG),
    ]


PMINIDUMP_MODULE_CALLBACK = POINTER(MINIDUMP_MODULE_CALLBACK)


# typedef struct _MINIDUMP_INCLUDE_THREAD_CALLBACK {
#   ULONG ThreadId;
# } MINIDUMP_INCLUDE_THREAD_CALLBACK, *PMINIDUMP_INCLUDE_THREAD_CALLBACK;
class MINIDUMP_INCLUDE_THREAD_CALLBACK(Structure):
    _fields_ = [
        ("ThreadId", ULONG),
    ]


PMINIDUMP_INCLUDE_THREAD_CALLBACK = POINTER(MINIDUMP_INCLUDE_THREAD_CALLBACK)


# typedef struct _MINIDUMP_INCLUDE_MODULE_CALLBACK {
#   ULONG64 BaseOfImage;
# } MINIDUMP_INCLUDE_MODULE_CALLBACK, *PMINIDUMP_INCLUDE_MODULE_CALLBACK;
class MINIDUMP_INCLUDE_MODULE_CALLBACK(Structure):
    _fields_ = [
        ("BaseOfImage", ULONG64),
    ]


PMINIDUMP_INCLUDE_MODULE_CALLBACK = POINTER(MINIDUMP_INCLUDE_MODULE_CALLBACK)


# typedef struct _MINIDUMP_IO_CALLBACK {
#   HANDLE  Handle;
#   ULONG64 Offset;
#   PVOID   Buffer;
#   ULONG   BufferBytes;
# } MINIDUMP_IO_CALLBACK, *PMINIDUMP_IO_CALLBACK;
class MINIDUMP_IO_CALLBACK(Structure):
    _fields_ = [
        ("Handle", HANDLE),
        ("Offset", ULONG64),
        ("Buffer", PVOID),
        ("BufferBytes", ULONG),
    ]


PMINIDUMP_IO_CALLBACK = POINTER(MINIDUMP_IO_CALLBACK)


# typedef struct _MINIDUMP_READ_MEMORY_FAILURE_CALLBACK {
#   ULONG64 Offset;
#   ULONG   Bytes;
#   HRESULT FailureStatus;
# } MINIDUMP_READ_MEMORY_FAILURE_CALLBACK, *PMINIDUMP_READ_MEMORY_FAILURE_CALLBACK;
class MINIDUMP_READ_MEMORY_FAILURE_CALLBACK(Structure):
    _fields_ = [
        ("Offset", ULONG64),
        ("Bytes", ULONG),
        ("FailureStatus", HRESULT),
    ]


PMINIDUMP_READ_MEMORY_FAILURE_CALLBACK = POINTER(MINIDUMP_READ_MEMORY_FAILURE_CALLBACK)


# typedef struct _MINIDUMP_VM_QUERY_CALLBACK {
#   ULONG64 Offset;
# } MINIDUMP_VM_QUERY_CALLBACK, *PMINIDUMP_VM_QUERY_CALLBACK;
class MINIDUMP_VM_QUERY_CALLBACK(Structure):
    _fields_ = [
        ("Offset", ULONG64),
    ]


PMINIDUMP_VM_QUERY_CALLBACK = POINTER(MINIDUMP_VM_QUERY_CALLBACK)


# typedef struct _MINIDUMP_VM_PRE_READ_CALLBACK {
#   ULONG64 Offset;
#   PVOID   Buffer;
#   ULONG   Size;
# } MINIDUMP_VM_PRE_READ_CALLBACK, *PMINIDUMP_VM_PRE_READ_CALLBACK;
class MINIDUMP_VM_PRE_READ_CALLBACK(Structure):
    _fields_ = [
        ("Offset", ULONG64),
        ("Buffer", PVOID),
        ("Size", ULONG),
    ]


PMINIDUMP_VM_PRE_READ_CALLBACK = POINTER(MINIDUMP_VM_PRE_READ_CALLBACK)


# typedef struct _MINIDUMP_VM_POST_READ_CALLBACK {
#   ULONG64 Offset;
#   PVOID   Buffer;
#   ULONG   Size;
#   ULONG   Completed;
# } MINIDUMP_VM_POST_READ_CALLBACK, *PMINIDUMP_VM_POST_READ_CALLBACK;
class MINIDUMP_VM_POST_READ_CALLBACK(Structure):
    _fields_ = [
        ("Offset", ULONG64),
        ("Buffer", PVOID),
        ("Size", ULONG),
        ("Completed", ULONG),
    ]


PMINIDUMP_VM_POST_READ_CALLBACK = POINTER(MINIDUMP_VM_POST_READ_CALLBACK)


# Union for MINIDUMP_CALLBACK_INPUT
class MINIDUMP_CALLBACK_INPUT_UNION(Union):
    _fields_ = [
        ("Status", HRESULT),
        ("Thread", MINIDUMP_THREAD_CALLBACK),
        ("ThreadEx", MINIDUMP_THREAD_EX_CALLBACK),
        ("Module", MINIDUMP_MODULE_CALLBACK),
        ("IncludeThread", MINIDUMP_INCLUDE_THREAD_CALLBACK),
        ("IncludeModule", MINIDUMP_INCLUDE_MODULE_CALLBACK),
        ("Io", MINIDUMP_IO_CALLBACK),
        ("ReadMemoryFailure", MINIDUMP_READ_MEMORY_FAILURE_CALLBACK),
        ("SecondaryFlags", ULONG),
        ("VmQuery", MINIDUMP_VM_QUERY_CALLBACK),
        ("VmPreRead", MINIDUMP_VM_PRE_READ_CALLBACK),
        ("VmPostRead", MINIDUMP_VM_POST_READ_CALLBACK),
    ]


# typedef struct _MINIDUMP_CALLBACK_INPUT {
#   ULONG  ProcessId;
#   HANDLE ProcessHandle;
#   ULONG  CallbackType;
#   union {
#     HRESULT                               Status;
#     MINIDUMP_THREAD_CALLBACK              Thread;
#     MINIDUMP_THREAD_EX_CALLBACK           ThreadEx;
#     MINIDUMP_MODULE_CALLBACK              Module;
#     MINIDUMP_INCLUDE_THREAD_CALLBACK      IncludeThread;
#     MINIDUMP_INCLUDE_MODULE_CALLBACK      IncludeModule;
#     MINIDUMP_IO_CALLBACK                  Io;
#     MINIDUMP_READ_MEMORY_FAILURE_CALLBACK ReadMemoryFailure;
#     ULONG                                 SecondaryFlags;
#     MINIDUMP_VM_QUERY_CALLBACK            VmQuery;
#     MINIDUMP_VM_PRE_READ_CALLBACK         VmPreRead;
#     MINIDUMP_VM_POST_READ_CALLBACK        VmPostRead;
#   };
# } MINIDUMP_CALLBACK_INPUT, *PMINIDUMP_CALLBACK_INPUT;
class MINIDUMP_CALLBACK_INPUT(Structure):
    _fields_ = [
        ("ProcessId", ULONG),
        ("ProcessHandle", HANDLE),
        ("CallbackType", ULONG),
        ("Union", MINIDUMP_CALLBACK_INPUT_UNION),
    ]


PMINIDUMP_CALLBACK_INPUT = POINTER(MINIDUMP_CALLBACK_INPUT)


# typedef struct _MINIDUMP_MEMORY_INFO {
#   ULONG64 BaseAddress;
#   ULONG64 AllocationBase;
#   ULONG32 AllocationProtect;
#   ULONG32 __alignment1;
#   ULONG64 RegionSize;
#   ULONG32 State;
#   ULONG32 Protect;
#   ULONG32 Type;
#   ULONG32 __alignment2;
# } MINIDUMP_MEMORY_INFO, *PMINIDUMP_MEMORY_INFO;
class MINIDUMP_MEMORY_INFO(Structure):
    _fields_ = [
        ("BaseAddress", ULONG64),
        ("AllocationBase", ULONG64),
        ("AllocationProtect", ULONG32),
        ("__alignment1", ULONG32),
        ("RegionSize", ULONG64),
        ("State", ULONG32),
        ("Protect", ULONG32),
        ("Type", ULONG32),
        ("__alignment2", ULONG32),
    ]


PMINIDUMP_MEMORY_INFO = POINTER(MINIDUMP_MEMORY_INFO)


# Anonymous structures used in MINIDUMP_CALLBACK_OUTPUT union
class MINIDUMP_CALLBACK_OUTPUT_MEMORY(Structure):
    _fields_ = [
        ("MemoryBase", ULONG64),
        ("MemorySize", ULONG),
    ]


class MINIDUMP_CALLBACK_OUTPUT_CANCEL(Structure):
    _fields_ = [
        ("CheckCancel", BOOL),
        ("Cancel", BOOL),
    ]


class MINIDUMP_CALLBACK_OUTPUT_VM_REGION(Structure):
    _fields_ = [
        ("VmRegion", MINIDUMP_MEMORY_INFO),
        ("Continue", BOOL),
    ]


class MINIDUMP_CALLBACK_OUTPUT_VM_QUERY(Structure):
    _fields_ = [
        ("VmQueryStatus", HRESULT),
        ("VmQueryResult", MINIDUMP_MEMORY_INFO),
    ]


class MINIDUMP_CALLBACK_OUTPUT_VM_READ(Structure):
    _fields_ = [
        ("VmReadStatus", HRESULT),
        ("VmReadBytesCompleted", ULONG),
    ]


# typedef struct _MINIDUMP_CALLBACK_OUTPUT {
#   union {
#     ULONG   ModuleWriteFlags;
#     ULONG   ThreadWriteFlags;
#     ULONG   SecondaryFlags;
#     struct {
#       ULONG64 MemoryBase;
#       ULONG   MemorySize;
#     };
#     struct {
#       BOOL CheckCancel;
#       BOOL Cancel;
#     };
#     HANDLE  Handle;
#     struct {
#       MINIDUMP_MEMORY_INFO VmRegion;
#       BOOL                 Continue;
#     };
#     struct {
#       HRESULT              VmQueryStatus;
#       MINIDUMP_MEMORY_INFO VmQueryResult;
#     };
#     struct {
#       HRESULT VmReadStatus;
#       ULONG   VmReadBytesCompleted;
#     };
#     HRESULT Status;
#   };
# } MINIDUMP_CALLBACK_OUTPUT, *PMINIDUMP_CALLBACK_OUTPUT;
class MINIDUMP_CALLBACK_OUTPUT(Union):
    _fields_ = [
        ("ModuleWriteFlags", ULONG),
        ("ThreadWriteFlags", ULONG),
        ("SecondaryFlags", ULONG),
        ("Memory", MINIDUMP_CALLBACK_OUTPUT_MEMORY),
        ("Cancel", MINIDUMP_CALLBACK_OUTPUT_CANCEL),
        ("Handle", HANDLE),
        ("VmRegion", MINIDUMP_CALLBACK_OUTPUT_VM_REGION),
        ("VmQuery", MINIDUMP_CALLBACK_OUTPUT_VM_QUERY),
        ("VmRead", MINIDUMP_CALLBACK_OUTPUT_VM_READ),
        ("Status", HRESULT),
    ]


PMINIDUMP_CALLBACK_OUTPUT = POINTER(MINIDUMP_CALLBACK_OUTPUT)


# typedef struct _EXCEPTION_RECORD {
#   DWORD                    ExceptionCode;
#   DWORD                    ExceptionFlags;
#   struct _EXCEPTION_RECORD *ExceptionRecord;
#   PVOID                    ExceptionAddress;
#   DWORD                    NumberParameters;
#   ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD;
class EXCEPTION_RECORD(Structure):
    pass  # must define fields below because it's recursive


PEXCEPTION_RECORD = POINTER(EXCEPTION_RECORD)

EXCEPTION_MAXIMUM_PARAMETERS = 15  # Standard value per Windows SDK

EXCEPTION_RECORD._fields_ = [
    ("ExceptionCode", DWORD),
    ("ExceptionFlags", DWORD),
    ("ExceptionRecord", PEXCEPTION_RECORD),
    ("ExceptionAddress", PVOID),
    ("NumberParameters", DWORD),
    ("ExceptionInformation", ULONG_PTR * EXCEPTION_MAXIMUM_PARAMETERS),
]


# typedef struct _EXCEPTION_RECORD32 {
#   DWORD    ExceptionCode;
#   DWORD ExceptionFlags;
#   DWORD ExceptionRecord;
#   DWORD ExceptionAddress;
#   DWORD NumberParameters;
#   DWORD ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;
class EXCEPTION_RECORD32(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD),
        ("ExceptionAddress", DWORD),
        ("NumberParameters", DWORD),
        ("ExceptionInformation", DWORD * EXCEPTION_MAXIMUM_PARAMETERS),
    ]


PEXCEPTION_RECORD32 = POINTER(EXCEPTION_RECORD32)


# typedef struct _EXCEPTION_RECORD64 {
#   DWORD    ExceptionCode;
#   DWORD ExceptionFlags;
#   DWORD64 ExceptionRecord;
#   DWORD64 ExceptionAddress;
#   DWORD NumberParameters;
#   DWORD __unusedAlignment;
#   DWORD64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# } EXCEPTION_RECORD64, *PEXCEPTION_RECORD64;
class EXCEPTION_RECORD64(Structure):
    _fields_ = [
        ("ExceptionCode", DWORD),
        ("ExceptionFlags", DWORD),
        ("ExceptionRecord", DWORD64),
        ("ExceptionAddress", DWORD64),
        ("NumberParameters", DWORD),
        ("__unusedAlignment", DWORD),
        ("ExceptionInformation", DWORD64 * EXCEPTION_MAXIMUM_PARAMETERS),
    ]


PEXCEPTION_RECORD64 = POINTER(EXCEPTION_RECORD64)


# typedef struct _EXCEPTION_POINTERS {
#   PEXCEPTION_RECORD ExceptionRecord;
#   PCONTEXT          ContextRecord;
# } EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
class EXCEPTION_POINTERS(Structure):
    _fields_ = [
        (
            "ExceptionRecord",
            PVOID,
        ),  # PEXCEPTION_RECORD, PEXCEPTION_RECORD32 or PEXCEPTION_RECORD64
        ("ContextRecord", PVOID),  # PCONTEXT (depends on target architecture)
    ]


PEXCEPTION_POINTERS = POINTER(EXCEPTION_POINTERS)


# typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
#   DWORD               ThreadId;
#   PEXCEPTION_POINTERS ExceptionPointers;
#   BOOL                ClientPointers;
# } MINIDUMP_EXCEPTION_INFORMATION, *PMINIDUMP_EXCEPTION_INFORMATION;
class MINIDUMP_EXCEPTION_INFORMATION(Structure):
    _fields_ = [
        ("ThreadId", DWORD),
        ("ExceptionPointers", PEXCEPTION_POINTERS),
        ("ClientPointers", BOOL),
    ]


PMINIDUMP_EXCEPTION_INFORMATION = POINTER(MINIDUMP_EXCEPTION_INFORMATION)


# typedef struct _MINIDUMP_USER_STREAM {
#   ULONG32 Type;
#   ULONG   BufferSize;
#   PVOID   Buffer;
# } MINIDUMP_USER_STREAM, *PMINIDUMP_USER_STREAM;
class MINIDUMP_USER_STREAM(Structure):
    _fields_ = [
        ("Type", ULONG32),
        ("BufferSize", ULONG),
        ("Buffer", PVOID),
    ]


PMINIDUMP_USER_STREAM = POINTER(MINIDUMP_USER_STREAM)


# typedef struct _MINIDUMP_USER_STREAM_INFORMATION {
#   ULONG                 UserStreamCount;
#   PMINIDUMP_USER_STREAM UserStreamArray;
# } MINIDUMP_USER_STREAM_INFORMATION, *PMINIDUMP_USER_STREAM_INFORMATION;
class MINIDUMP_USER_STREAM_INFORMATION(Structure):
    _fields_ = [
        ("UserStreamCount", ULONG),
        ("UserStreamArray", PMINIDUMP_USER_STREAM),
    ]


PMINIDUMP_USER_STREAM_INFORMATION = POINTER(MINIDUMP_USER_STREAM_INFORMATION)

# BOOL CALLBACK MiniDumpCallback(
#   [in]      PVOID CallbackParam,
#   [in]      PMINIDUMP_CALLBACK_INPUT CallbackInput,
#   [in, out] PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
# );
MINIDUMP_CALLBACK_ROUTINE = WINFUNCTYPE(
    BOOL,
    PVOID,  # CallbackParam
    PMINIDUMP_CALLBACK_INPUT,  # CallbackInput
    PMINIDUMP_CALLBACK_OUTPUT,  # CallbackOutput
)


# typedef struct _MINIDUMP_CALLBACK_INFORMATION {
#   MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
#   PVOID                     CallbackParam;
# } MINIDUMP_CALLBACK_INFORMATION, *PMINIDUMP_CALLBACK_INFORMATION;
class MINIDUMP_CALLBACK_INFORMATION(Structure):
    _fields_ = [
        ("CallbackRoutine", PVOID),  # Function pointer (MINIDUMP_CALLBACK_ROUTINE)
        ("CallbackParam", PVOID),
    ]


PMINIDUMP_CALLBACK_INFORMATION = POINTER(MINIDUMP_CALLBACK_INFORMATION)


# --- dbghelp.dll --------------------------------------------------------------

# XXX the ANSI versions of these functions don't end in "A" as expected!


# BOOL WINAPI MakeSureDirectoryPathExists(
#   _In_  PCSTR DirPath
# );
def MakeSureDirectoryPathExistsA(DirPath):
    _MakeSureDirectoryPathExists = windll.dbghelp.MakeSureDirectoryPathExists
    _MakeSureDirectoryPathExists.argtypes = [LPSTR]
    _MakeSureDirectoryPathExists.restype = bool
    _MakeSureDirectoryPathExists.errcheck = RaiseIfZero
    return _MakeSureDirectoryPathExists(DirPath)


MakeSureDirectoryPathExistsW = MakeWideVersion(MakeSureDirectoryPathExistsA)
MakeSureDirectoryPathExists = GuessStringType(
    MakeSureDirectoryPathExistsA, MakeSureDirectoryPathExistsW
)


# BOOL WINAPI SymInitialize(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR UserSearchPath,
#   __in      BOOL fInvadeProcess
# );
def SymInitializeA(hProcess, UserSearchPath=None, fInvadeProcess=False):
    _SymInitialize = windll.dbghelp.SymInitialize
    _SymInitialize.argtypes = [HANDLE, LPSTR, BOOL]
    _SymInitialize.restype = bool
    _SymInitialize.errcheck = RaiseIfZero
    if not UserSearchPath:
        UserSearchPath = None
    _SymInitialize(hProcess, UserSearchPath, fInvadeProcess)


def SymInitializeW(hProcess, UserSearchPath=None, fInvadeProcess=False):
    _SymInitializeW = windll.dbghelp.SymInitializeW
    _SymInitializeW.argtypes = [HANDLE, LPWSTR, BOOL]
    _SymInitializeW.restype = bool
    _SymInitializeW.errcheck = RaiseIfZero
    if not UserSearchPath:
        UserSearchPath = None
    _SymInitializeW(hProcess, UserSearchPath, fInvadeProcess)


SymInitialize = GuessStringType(SymInitializeA, SymInitializeW)


# BOOL WINAPI SymCleanup(
#   __in  HANDLE hProcess
# );
def SymCleanup(hProcess):
    _SymCleanup = windll.dbghelp.SymCleanup
    _SymCleanup.argtypes = [HANDLE]
    _SymCleanup.restype = bool
    _SymCleanup.errcheck = RaiseIfZero
    _SymCleanup(hProcess)


# BOOL WINAPI SymRefreshModuleList(
#   __in  HANDLE hProcess
# );
def SymRefreshModuleList(hProcess):
    _SymRefreshModuleList = windll.dbghelp.SymRefreshModuleList
    _SymRefreshModuleList.argtypes = [HANDLE]
    _SymRefreshModuleList.restype = bool
    _SymRefreshModuleList.errcheck = RaiseIfZero
    _SymRefreshModuleList(hProcess)


# BOOL WINAPI SymSetParentWindow(
#   __in  HWND hwnd
# );
def SymSetParentWindow(hwnd):
    _SymSetParentWindow = windll.dbghelp.SymSetParentWindow
    _SymSetParentWindow.argtypes = [HWND]
    _SymSetParentWindow.restype = bool
    _SymSetParentWindow.errcheck = RaiseIfZero
    _SymSetParentWindow(hwnd)


# DWORD WINAPI SymSetOptions(
#   __in  DWORD SymOptions
# );
def SymSetOptions(SymOptions):
    _SymSetOptions = windll.dbghelp.SymSetOptions
    _SymSetOptions.argtypes = [DWORD]
    _SymSetOptions.restype = DWORD
    _SymSetOptions.errcheck = RaiseIfZero
    _SymSetOptions(SymOptions)


# DWORD WINAPI SymGetOptions(void);
def SymGetOptions():
    _SymGetOptions = windll.dbghelp.SymGetOptions
    _SymGetOptions.argtypes = []
    _SymGetOptions.restype = DWORD
    return _SymGetOptions()


# DWORD WINAPI SymLoadModule(
#   __in      HANDLE hProcess,
#   __in_opt  HANDLE hFile,
#   __in_opt  PCSTR ImageName,
#   __in_opt  PCSTR ModuleName,
#   __in      DWORD BaseOfDll,
#   __in      DWORD SizeOfDll
# );
def SymLoadModuleA(
    hProcess,
    hFile=None,
    ImageName=None,
    ModuleName=None,
    BaseOfDll=None,
    SizeOfDll=None,
):
    _SymLoadModule = windll.dbghelp.SymLoadModule
    _SymLoadModule.argtypes = [HANDLE, HANDLE, LPSTR, LPSTR, DWORD, DWORD]
    _SymLoadModule.restype = DWORD

    if not ImageName:
        ImageName = None
    if not ModuleName:
        ModuleName = None
    if not BaseOfDll:
        BaseOfDll = 0
    if not SizeOfDll:
        SizeOfDll = 0
    SetLastError(ERROR_SUCCESS)
    lpBaseAddress = _SymLoadModule(
        hProcess, hFile, ImageName, ModuleName, BaseOfDll, SizeOfDll
    )
    if lpBaseAddress == NULL:
        dwErrorCode = GetLastError()
        if dwErrorCode != ERROR_SUCCESS:
            raise ctypes.WinError(dwErrorCode)
    return lpBaseAddress


SymLoadModuleW = MakeWideVersion(SymLoadModuleA)
SymLoadModule = GuessStringType(SymLoadModuleA, SymLoadModuleW)


# DWORD64 WINAPI SymLoadModule64(
#   __in      HANDLE hProcess,
#   __in_opt  HANDLE hFile,
#   __in_opt  PCSTR ImageName,
#   __in_opt  PCSTR ModuleName,
#   __in      DWORD64 BaseOfDll,
#   __in      DWORD SizeOfDll
# );
def SymLoadModule64A(
    hProcess,
    hFile=None,
    ImageName=None,
    ModuleName=None,
    BaseOfDll=None,
    SizeOfDll=None,
):
    _SymLoadModule64 = windll.dbghelp.SymLoadModule64
    _SymLoadModule64.argtypes = [HANDLE, HANDLE, LPSTR, LPSTR, DWORD64, DWORD]
    _SymLoadModule64.restype = DWORD64

    if not ImageName:
        ImageName = None
    if not ModuleName:
        ModuleName = None
    if not BaseOfDll:
        BaseOfDll = 0
    if not SizeOfDll:
        SizeOfDll = 0
    SetLastError(ERROR_SUCCESS)
    lpBaseAddress = _SymLoadModule64(
        hProcess, hFile, ImageName, ModuleName, BaseOfDll, SizeOfDll
    )
    if lpBaseAddress == NULL:
        dwErrorCode = GetLastError()
        if dwErrorCode != ERROR_SUCCESS:
            raise ctypes.WinError(dwErrorCode)
    return lpBaseAddress


SymLoadModule64W = MakeWideVersion(SymLoadModule64A)
SymLoadModule64 = GuessStringType(SymLoadModule64A, SymLoadModule64W)


# BOOL WINAPI SymUnloadModule(
#   __in  HANDLE hProcess,
#   __in  DWORD BaseOfDll
# );
def SymUnloadModule(hProcess, BaseOfDll):
    _SymUnloadModule = windll.dbghelp.SymUnloadModule
    _SymUnloadModule.argtypes = [HANDLE, DWORD]
    _SymUnloadModule.restype = bool
    _SymUnloadModule.errcheck = RaiseIfZero
    _SymUnloadModule(hProcess, BaseOfDll)


# BOOL WINAPI SymUnloadModule64(
#   __in  HANDLE hProcess,
#   __in  DWORD64 BaseOfDll
# );
def SymUnloadModule64(hProcess, BaseOfDll):
    _SymUnloadModule64 = windll.dbghelp.SymUnloadModule64
    _SymUnloadModule64.argtypes = [HANDLE, DWORD64]
    _SymUnloadModule64.restype = bool
    _SymUnloadModule64.errcheck = RaiseIfZero
    _SymUnloadModule64(hProcess, BaseOfDll)


# BOOL WINAPI SymGetModuleInfo(
#   __in   HANDLE hProcess,
#   __in   DWORD dwAddr,
#   __out  PIMAGEHLP_MODULE ModuleInfo
# );
def SymGetModuleInfoA(hProcess, dwAddr):
    _SymGetModuleInfo = windll.dbghelp.SymGetModuleInfo
    _SymGetModuleInfo.argtypes = [HANDLE, DWORD, PIMAGEHLP_MODULE]
    _SymGetModuleInfo.restype = bool
    _SymGetModuleInfo.errcheck = RaiseIfZero

    ModuleInfo = IMAGEHLP_MODULE()
    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo)
    _SymGetModuleInfo(hProcess, dwAddr, byref(ModuleInfo))
    return ModuleInfo


SymGetModuleInfoW = MakeWideVersion(SymGetModuleInfoA)
SymGetModuleInfo = GuessStringType(SymGetModuleInfoA, SymGetModuleInfoW)


# BOOL WINAPI SymGetModuleInfo64(
#   __in   HANDLE hProcess,
#   __in   DWORD64 dwAddr,
#   __out  PIMAGEHLP_MODULE64 ModuleInfo
# );
def SymGetModuleInfo64A(hProcess, dwAddr):
    _SymGetModuleInfo64 = windll.dbghelp.SymGetModuleInfo64
    _SymGetModuleInfo64.argtypes = [HANDLE, DWORD64, PIMAGEHLP_MODULE64]
    _SymGetModuleInfo64.restype = bool
    _SymGetModuleInfo64.errcheck = RaiseIfZero

    ModuleInfo = IMAGEHLP_MODULE64()
    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo)
    _SymGetModuleInfo64(hProcess, dwAddr, byref(ModuleInfo))
    return ModuleInfo


SymGetModuleInfo64W = MakeWideVersion(SymGetModuleInfo64A)
SymGetModuleInfo64 = GuessStringType(SymGetModuleInfo64A, SymGetModuleInfo64W)

# BOOL CALLBACK SymEnumerateModulesProc(
#   __in      PCTSTR ModuleName,
#   __in      DWORD BaseOfDll,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMMODULES_CALLBACK = WINFUNCTYPE(BOOL, LPSTR, DWORD, PVOID)
PSYM_ENUMMODULES_CALLBACKW = WINFUNCTYPE(BOOL, LPWSTR, DWORD, PVOID)

# BOOL CALLBACK SymEnumerateModulesProc64(
#   __in      PCTSTR ModuleName,
#   __in      DWORD64 BaseOfDll,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMMODULES_CALLBACK64 = WINFUNCTYPE(BOOL, LPSTR, DWORD64, PVOID)
PSYM_ENUMMODULES_CALLBACKW64 = WINFUNCTYPE(BOOL, LPWSTR, DWORD64, PVOID)


# BOOL WINAPI SymEnumerateModules(
#   __in      HANDLE hProcess,
#   __in      PSYM_ENUMMODULES_CALLBACK EnumModulesCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateModulesA(hProcess, EnumModulesCallback, UserContext=None):
    _SymEnumerateModules = windll.dbghelp.SymEnumerateModules
    _SymEnumerateModules.argtypes = [HANDLE, PSYM_ENUMMODULES_CALLBACK, PVOID]
    _SymEnumerateModules.restype = bool
    _SymEnumerateModules.errcheck = RaiseIfZero

    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACK(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateModules(hProcess, EnumModulesCallback, UserContext)


def SymEnumerateModulesW(hProcess, EnumModulesCallback, UserContext=None):
    _SymEnumerateModulesW = windll.dbghelp.SymEnumerateModulesW
    _SymEnumerateModulesW.argtypes = [HANDLE, PSYM_ENUMMODULES_CALLBACKW, PVOID]
    _SymEnumerateModulesW.restype = bool
    _SymEnumerateModulesW.errcheck = RaiseIfZero

    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACKW(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateModulesW(hProcess, EnumModulesCallback, UserContext)


SymEnumerateModules = GuessStringType(SymEnumerateModulesA, SymEnumerateModulesW)


# BOOL WINAPI SymEnumerateModules64(
#   __in      HANDLE hProcess,
#   __in      PSYM_ENUMMODULES_CALLBACK64 EnumModulesCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateModules64A(hProcess, EnumModulesCallback, UserContext=None):
    _SymEnumerateModules64 = windll.dbghelp.SymEnumerateModules64
    _SymEnumerateModules64.argtypes = [HANDLE, PSYM_ENUMMODULES_CALLBACK64, PVOID]
    _SymEnumerateModules64.restype = bool
    _SymEnumerateModules64.errcheck = RaiseIfZero

    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACK64(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateModules64(hProcess, EnumModulesCallback, UserContext)


SymEnumerateModules64W = MakeWideVersion(SymEnumerateModules64A)
SymEnumerateModules64 = GuessStringType(SymEnumerateModules64A, SymEnumerateModules64W)

# BOOL CALLBACK SymEnumerateSymbolsProc(
#   __in      PCTSTR SymbolName,
#   __in      DWORD SymbolAddress,
#   __in      ULONG SymbolSize,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMSYMBOLS_CALLBACK = WINFUNCTYPE(BOOL, LPSTR, DWORD, ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW = WINFUNCTYPE(BOOL, LPWSTR, DWORD, ULONG, PVOID)

# BOOL CALLBACK SymEnumerateSymbolsProc64(
#   __in      PCTSTR SymbolName,
#   __in      DWORD64 SymbolAddress,
#   __in      ULONG SymbolSize,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMSYMBOLS_CALLBACK64 = WINFUNCTYPE(BOOL, LPSTR, DWORD64, ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW64 = WINFUNCTYPE(BOOL, LPWSTR, DWORD64, ULONG, PVOID)


# BOOL WINAPI SymEnumerateSymbols(
#   __in      HANDLE hProcess,
#   __in      ULONG BaseOfDll,
#   __in      PSYM_ENUMSYMBOLS_CALLBACK EnumSymbolsCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateSymbolsA(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext=None):
    _SymEnumerateSymbols = windll.dbghelp.SymEnumerateSymbols
    _SymEnumerateSymbols.argtypes = [HANDLE, ULONG, PSYM_ENUMSYMBOLS_CALLBACK, PVOID]
    _SymEnumerateSymbols.restype = bool
    _SymEnumerateSymbols.errcheck = RaiseIfZero

    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACK(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateSymbols(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)


def SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext=None):
    _SymEnumerateSymbolsW = windll.dbghelp.SymEnumerateSymbolsW
    _SymEnumerateSymbolsW.argtypes = [HANDLE, ULONG, PSYM_ENUMSYMBOLS_CALLBACKW, PVOID]
    _SymEnumerateSymbolsW.restype = bool
    _SymEnumerateSymbolsW.errcheck = RaiseIfZero

    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACKW(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)


SymEnumerateSymbols = GuessStringType(SymEnumerateSymbolsA, SymEnumerateSymbolsW)


# BOOL WINAPI SymEnumerateSymbols64(
#   __in      HANDLE hProcess,
#   __in      ULONG64 BaseOfDll,
#   __in      PSYM_ENUMSYMBOLS_CALLBACK64 EnumSymbolsCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateSymbols64A(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext=None):
    _SymEnumerateSymbols64 = windll.dbghelp.SymEnumerateSymbols64
    _SymEnumerateSymbols64.argtypes = [
        HANDLE,
        ULONG64,
        PSYM_ENUMSYMBOLS_CALLBACK64,
        PVOID,
    ]
    _SymEnumerateSymbols64.restype = bool
    _SymEnumerateSymbols64.errcheck = RaiseIfZero

    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACK64(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    _SymEnumerateSymbols64(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)


SymEnumerateSymbols64W = MakeWideVersion(SymEnumerateSymbols64A)
SymEnumerateSymbols64 = GuessStringType(SymEnumerateSymbols64A, SymEnumerateSymbols64W)


# DWORD WINAPI UnDecorateSymbolName(
#   __in   PCTSTR DecoratedName,
#   __out  PTSTR UnDecoratedName,
#   __in   DWORD UndecoratedLength,
#   __in   DWORD Flags
# );
def UnDecorateSymbolNameA(DecoratedName, Flags=UNDNAME_COMPLETE):
    _UnDecorateSymbolNameA = windll.dbghelp.UnDecorateSymbolName
    _UnDecorateSymbolNameA.argtypes = [LPSTR, LPSTR, DWORD, DWORD]
    _UnDecorateSymbolNameA.restype = DWORD
    _UnDecorateSymbolNameA.errcheck = RaiseIfZero

    UndecoratedLength = _UnDecorateSymbolNameA(DecoratedName, None, 0, Flags)
    UnDecoratedName = ctypes.create_string_buffer("", UndecoratedLength + 1)
    _UnDecorateSymbolNameA(DecoratedName, UnDecoratedName, UndecoratedLength, Flags)
    return UnDecoratedName.value


def UnDecorateSymbolNameW(DecoratedName, Flags=UNDNAME_COMPLETE):
    _UnDecorateSymbolNameW = windll.dbghelp.UnDecorateSymbolNameW
    _UnDecorateSymbolNameW.argtypes = [LPWSTR, LPWSTR, DWORD, DWORD]
    _UnDecorateSymbolNameW.restype = DWORD
    _UnDecorateSymbolNameW.errcheck = RaiseIfZero

    UndecoratedLength = _UnDecorateSymbolNameW(DecoratedName, None, 0, Flags)
    UnDecoratedName = ctypes.create_unicode_buffer("", UndecoratedLength + 1)
    _UnDecorateSymbolNameW(DecoratedName, UnDecoratedName, UndecoratedLength, Flags)
    return UnDecoratedName.value


UnDecorateSymbolName = GuessStringType(UnDecorateSymbolNameA, UnDecorateSymbolNameW)


# BOOL WINAPI SymGetSearchPath(
#   __in   HANDLE hProcess,
#   __out  PTSTR SearchPath,
#   __in   DWORD SearchPathLength
# );
def SymGetSearchPathA(hProcess):
    _SymGetSearchPath = windll.dbghelp.SymGetSearchPath
    _SymGetSearchPath.argtypes = [HANDLE, LPSTR, DWORD]
    _SymGetSearchPath.restype = bool
    _SymGetSearchPath.errcheck = RaiseIfZero

    SearchPathLength = MAX_PATH
    SearchPath = ctypes.create_string_buffer("", SearchPathLength)
    _SymGetSearchPath(hProcess, SearchPath, SearchPathLength)
    return SearchPath.value


def SymGetSearchPathW(hProcess):
    _SymGetSearchPathW = windll.dbghelp.SymGetSearchPathW
    _SymGetSearchPathW.argtypes = [HANDLE, LPWSTR, DWORD]
    _SymGetSearchPathW.restype = bool
    _SymGetSearchPathW.errcheck = RaiseIfZero

    SearchPathLength = MAX_PATH
    SearchPath = ctypes.create_unicode_buffer("", SearchPathLength)
    _SymGetSearchPathW(hProcess, SearchPath, SearchPathLength)
    return SearchPath.value


SymGetSearchPath = GuessStringType(SymGetSearchPathA, SymGetSearchPathW)


# BOOL WINAPI SymSetSearchPath(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR SearchPath
# );
def SymSetSearchPathA(hProcess, SearchPath=None):
    _SymSetSearchPath = windll.dbghelp.SymSetSearchPath
    _SymSetSearchPath.argtypes = [HANDLE, LPSTR]
    _SymSetSearchPath.restype = bool
    _SymSetSearchPath.errcheck = RaiseIfZero
    if not SearchPath:
        SearchPath = None
    _SymSetSearchPath(hProcess, SearchPath)


def SymSetSearchPathW(hProcess, SearchPath=None):
    _SymSetSearchPathW = windll.dbghelp.SymSetSearchPathW
    _SymSetSearchPathW.argtypes = [HANDLE, LPWSTR]
    _SymSetSearchPathW.restype = bool
    _SymSetSearchPathW.errcheck = RaiseIfZero
    if not SearchPath:
        SearchPath = None
    _SymSetSearchPathW(hProcess, SearchPath)


SymSetSearchPath = GuessStringType(SymSetSearchPathA, SymSetSearchPathW)


# PTCHAR WINAPI SymGetHomeDirectory(
#   __in   DWORD type,
#   __out  PTSTR dir,
#   __in   size_t size
# );
def SymGetHomeDirectoryA(type):
    _SymGetHomeDirectoryA = windll.dbghelp.SymGetHomeDirectoryA
    _SymGetHomeDirectoryA.argtypes = [DWORD, LPSTR, SIZE_T]
    _SymGetHomeDirectoryA.restype = LPSTR
    _SymGetHomeDirectoryA.errcheck = RaiseIfZero

    size = MAX_PATH
    dir = ctypes.create_string_buffer("", size)
    _SymGetHomeDirectoryA(type, dir, size)
    return dir.value


def SymGetHomeDirectoryW(type):
    _SymGetHomeDirectoryW = windll.dbghelp.SymGetHomeDirectoryW
    _SymGetHomeDirectoryW.argtypes = [DWORD, LPWSTR, SIZE_T]
    _SymGetHomeDirectoryW.restype = LPWSTR
    _SymGetHomeDirectoryW.errcheck = RaiseIfZero

    size = MAX_PATH
    dir = ctypes.create_unicode_buffer("", size)
    _SymGetHomeDirectoryW(type, dir, size)
    return dir.value


SymGetHomeDirectory = GuessStringType(SymGetHomeDirectoryA, SymGetHomeDirectoryW)


# PTCHAR WINAPI SymSetHomeDirectory(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR dir
# );
def SymSetHomeDirectoryA(hProcess, dir=None):
    _SymSetHomeDirectoryA = windll.dbghelp.SymSetHomeDirectoryA
    _SymSetHomeDirectoryA.argtypes = [HANDLE, LPSTR]
    _SymSetHomeDirectoryA.restype = LPSTR
    _SymSetHomeDirectoryA.errcheck = RaiseIfZero
    if not dir:
        dir = None
    _SymSetHomeDirectoryA(hProcess, dir)
    return dir


def SymSetHomeDirectoryW(hProcess, dir=None):
    _SymSetHomeDirectoryW = windll.dbghelp.SymSetHomeDirectoryW
    _SymSetHomeDirectoryW.argtypes = [HANDLE, LPWSTR]
    _SymSetHomeDirectoryW.restype = LPWSTR
    _SymSetHomeDirectoryW.errcheck = RaiseIfZero
    if not dir:
        dir = None
    _SymSetHomeDirectoryW(hProcess, dir)
    return dir


SymSetHomeDirectory = GuessStringType(SymSetHomeDirectoryA, SymSetHomeDirectoryW)


# BOOL MiniDumpWriteDump(
#   [in] HANDLE                            hProcess,
#   [in] DWORD                             ProcessId,
#   [in] HANDLE                            hFile,
#   [in] MINIDUMP_TYPE                     DumpType,
#   [in] PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
#   [in] PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
#   [in] PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
# );
def MiniDumpWriteDump(
    hProcess,
    ProcessId,
    hFile,
    ContextRecord,
    DumpType=MiniDumpNormal,
    ExceptionParam=NULL,
    UserStreamParam=NULL,
    CallbackParam=NULL,
):
    _MiniDumpWriteDump = windll.dbghelp.MiniDumpWriteDump
    _MiniDumpWriteDump.argtypes = [
        HANDLE,
        DWORD,
        HANDLE,
        PVOID,  # PCONTEXT, depends on target architecture
        MINIDUMP_TYPE,
        PMINIDUMP_EXCEPTION_INFORMATION,
        PMINIDUMP_USER_STREAM_INFORMATION,
        PMINIDUMP_CALLBACK_INFORMATION,
    ]
    _MiniDumpWriteDump.restype = bool
    _MiniDumpWriteDump.errcheck = RaiseIfZero
    _MiniDumpWriteDump(
        hProcess,
        ProcessId,
        hFile,
        ContextRecord,
        DumpType,
        ExceptionParam,
        UserStreamParam,
        CallbackParam,
    )


# --- DbgHelp 5+ support, patch by Neitsa --------------------------------------

# XXX TODO
# + use the GuessStringType decorator for ANSI/Wide versions
# + replace hardcoded struct sizes with sizeof() calls
# + StackWalk64 should raise on error, but something has to be done about it
#   not setting the last error code (maybe we should call SetLastError
#   ourselves with a default error code?)
# /Mario

# maximum length of a symbol name
MAX_SYM_NAME = 2000


class SYM_INFO(Structure):
    _fields_ = [
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * 2),
        ("Index", ULONG),
        ("Size", ULONG),
        ("ModBase", ULONG64),
        ("Flags", ULONG),
        ("Value", ULONG64),
        ("Address", ULONG64),
        ("Register", ULONG),
        ("Scope", ULONG),
        ("Tag", ULONG),
        ("NameLen", ULONG),
        ("MaxNameLen", ULONG),
        ("Name", CHAR * (MAX_SYM_NAME + 1)),
    ]


PSYM_INFO = POINTER(SYM_INFO)


class SYM_INFOW(Structure):
    _fields_ = [
        ("SizeOfStruct", ULONG),
        ("TypeIndex", ULONG),
        ("Reserved", ULONG64 * 2),
        ("Index", ULONG),
        ("Size", ULONG),
        ("ModBase", ULONG64),
        ("Flags", ULONG),
        ("Value", ULONG64),
        ("Address", ULONG64),
        ("Register", ULONG),
        ("Scope", ULONG),
        ("Tag", ULONG),
        ("NameLen", ULONG),
        ("MaxNameLen", ULONG),
        ("Name", WCHAR * (MAX_SYM_NAME + 1)),
    ]


PSYM_INFOW = POINTER(SYM_INFOW)


# ===============================================================================
# BOOL WINAPI SymFromName(
#  __in     HANDLE hProcess,
#  __in     PCTSTR Name,
#  __inout  PSYMBOL_INFO Symbol
# );
# ===============================================================================
def SymFromName(hProcess, Name):
    _SymFromNameA = windll.dbghelp.SymFromName
    _SymFromNameA.argtypes = [HANDLE, LPSTR, PSYM_INFO]
    _SymFromNameA.restype = bool
    _SymFromNameA.errcheck = RaiseIfZero

    SymInfo = SYM_INFO()
    SymInfo.SizeOfStruct = sizeof(SymInfo)
    SymInfo.MaxNameLen = MAX_SYM_NAME

    _SymFromNameA(hProcess, Name, byref(SymInfo))

    return SymInfo


def SymFromNameW(hProcess, Name):
    _SymFromNameW = windll.dbghelp.SymFromNameW
    _SymFromNameW.argtypes = [HANDLE, LPWSTR, PSYM_INFOW]
    _SymFromNameW.restype = bool
    _SymFromNameW.errcheck = RaiseIfZero

    SymInfo = SYM_INFOW()
    SymInfo.SizeOfStruct = sizeof(SymInfo)
    SymInfo.MaxNameLen = MAX_SYM_NAME

    _SymFromNameW(hProcess, Name, byref(SymInfo))

    return SymInfo


# ===============================================================================
# BOOL WINAPI SymFromAddr(
#  __in       HANDLE hProcess,
#  __in       DWORD64 Address,
#  __out_opt  PDWORD64 Displacement,
#  __inout    PSYMBOL_INFO Symbol
# );
# ===============================================================================
def SymFromAddr(hProcess, Address):
    _SymFromAddr = windll.dbghelp.SymFromAddr
    _SymFromAddr.argtypes = [HANDLE, DWORD64, PDWORD64, PSYM_INFO]
    _SymFromAddr.restype = bool
    _SymFromAddr.errcheck = RaiseIfZero

    SymInfo = SYM_INFO()
    SymInfo.SizeOfStruct = sizeof(SymInfo)
    SymInfo.MaxNameLen = MAX_SYM_NAME

    Displacement = DWORD64(0)
    _SymFromAddr(hProcess, Address, byref(Displacement), byref(SymInfo))

    return (Displacement.value, SymInfo)


def SymFromAddrW(hProcess, Address):
    _SymFromAddr = windll.dbghelp.SymFromAddrW
    _SymFromAddr.argtypes = [HANDLE, DWORD64, PDWORD64, PSYM_INFOW]
    _SymFromAddr.restype = bool
    _SymFromAddr.errcheck = RaiseIfZero

    SymInfo = SYM_INFOW()
    SymInfo.SizeOfStruct = sizeof(SymInfo)
    SymInfo.MaxNameLen = MAX_SYM_NAME

    Displacement = DWORD64(0)
    _SymFromAddr(hProcess, Address, byref(Displacement), byref(SymInfo))

    return (Displacement.value, SymInfo)


# ===============================================================================
# typedef struct _IMAGEHLP_SYMBOL64 {
#  DWORD   SizeOfStruct;
#  DWORD64 Address;
#  DWORD   Size;
#  DWORD   Flags;
#  DWORD   MaxNameLength;
#  CHAR   Name[1];
# } IMAGEHLP_SYMBOL64, *PIMAGEHLP_SYMBOL64;
# ===============================================================================
class IMAGEHLP_SYMBOL64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("Address", DWORD64),
        ("Size", DWORD),
        ("Flags", DWORD),
        ("MaxNameLength", DWORD),
        ("Name", CHAR * (MAX_SYM_NAME + 1)),
    ]


PIMAGEHLP_SYMBOL64 = POINTER(IMAGEHLP_SYMBOL64)


# ===============================================================================
# typedef struct _IMAGEHLP_SYMBOLW64 {
#  DWORD   SizeOfStruct;
#  DWORD64 Address;
#  DWORD   Size;
#  DWORD   Flags;
#  DWORD   MaxNameLength;
#  WCHAR   Name[1];
# } IMAGEHLP_SYMBOLW64, *PIMAGEHLP_SYMBOLW64;
# ===============================================================================
class IMAGEHLP_SYMBOLW64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("Address", DWORD64),
        ("Size", DWORD),
        ("Flags", DWORD),
        ("MaxNameLength", DWORD),
        ("Name", WCHAR * (MAX_SYM_NAME + 1)),
    ]


PIMAGEHLP_SYMBOLW64 = POINTER(IMAGEHLP_SYMBOLW64)


# ===============================================================================
# BOOL WINAPI SymGetSymFromAddr64(
#  __in       HANDLE hProcess,
#  __in       DWORD64 Address,
#  __out_opt  PDWORD64 Displacement,
#  __inout    PIMAGEHLP_SYMBOL64 Symbol
# );
# ===============================================================================
def SymGetSymFromAddr64A(hProcess, Address):
    _SymGetSymFromAddr64 = windll.dbghelp.SymGetSymFromAddr64
    _SymGetSymFromAddr64.argtypes = [HANDLE, DWORD64, PDWORD64, PIMAGEHLP_SYMBOL64]
    _SymGetSymFromAddr64.restype = bool
    _SymGetSymFromAddr64.errcheck = RaiseIfZero

    imagehlp_symbol64 = IMAGEHLP_SYMBOL64()
    imagehlp_symbol64.SizeOfStruct = sizeof(imagehlp_symbol64)
    imagehlp_symbol64.MaxNameLength = MAX_SYM_NAME

    Displacement = DWORD64(0)
    _SymGetSymFromAddr64(
        hProcess, Address, byref(Displacement), byref(imagehlp_symbol64)
    )

    return (Displacement.value, imagehlp_symbol64)


SymGetSymFromAddr64W = MakeWideVersion(SymGetSymFromAddr64A)
SymGetSymFromAddr64 = GuessStringType(SymGetSymFromAddr64A, SymGetSymFromAddr64W)


# ===============================================================================
# typedef struct _IMAGEHLP_LINE64 {
#  DWORD   SizeOfStruct;
#  PVOID   Key;
#  DWORD   LineNumber;
#  PSTR    FileName;
#  DWORD64 Address;
# } IMAGEHLP_LINE64, *PIMAGEHLP_LINE64;
# ===============================================================================
class IMAGEHLP_LINE64(Structure):
    _fields_ = [
        ("SizeOfStruct", DWORD),
        ("Key", PVOID),
        ("LineNumber", DWORD),
        ("FileName", PSTR),
        ("Address", DWORD64),
    ]


PIMAGEHLP_LINE64 = POINTER(IMAGEHLP_LINE64)


# ===============================================================================
# BOOL WINAPI SymGetLineFromAddr64(
#  __in  HANDLE           hProcess,
#  __in  DWORD64          dwAddr,
#  __out PDWORD           pdwDisplacement,
#  __out PIMAGEHLP_LINE64 Line
# );
# ===============================================================================
def SymGetLineFromAddr64A(hProcess, dwAddr):
    _SymGetLineFromAddr64 = windll.dbghelp.SymGetLineFromAddr64
    _SymGetLineFromAddr64.argtypes = [HANDLE, DWORD64, PDWORD, PIMAGEHLP_LINE64]
    _SymGetLineFromAddr64.restype = bool
    _SymGetLineFromAddr64.errcheck = RaiseIfZero

    imagehlp_line64 = IMAGEHLP_LINE64()
    imagehlp_line64.SizeOfStruct = sizeof(imagehlp_line64)

    pdwDisplacement = DWORD(0)
    _SymGetLineFromAddr64(
        hProcess, dwAddr, byref(pdwDisplacement), byref(imagehlp_line64)
    )

    return (pdwDisplacement.value, imagehlp_line64)


SymGetLineFromAddr64W = MakeWideVersion(SymGetLineFromAddr64A)
SymGetLineFromAddr64 = GuessStringType(SymGetLineFromAddr64A, SymGetLineFromAddr64W)


# ===============================================================================
# typedef struct API_VERSION {
#  USHORT MajorVersion;
#  USHORT MinorVersion;
#  USHORT Revision;
#  USHORT Reserved;
# } API_VERSION, *LPAPI_VERSION;
# ===============================================================================
class API_VERSION(Structure):
    _fields_ = [
        ("MajorVersion", USHORT),
        ("MinorVersion", USHORT),
        ("Revision", USHORT),
        ("Reserved", USHORT),
    ]


PAPI_VERSION = POINTER(API_VERSION)
LPAPI_VERSION = PAPI_VERSION


# ===============================================================================
# LPAPI_VERSION WINAPI ImagehlpApiVersion(void);
# ===============================================================================
def ImagehlpApiVersion():
    _ImagehlpApiVersion = windll.dbghelp.ImagehlpApiVersion
    _ImagehlpApiVersion.restype = LPAPI_VERSION

    api_version = _ImagehlpApiVersion()
    return api_version.contents


# ===============================================================================
# LPAPI_VERSION WINAPI ImagehlpApiVersionEx(
#  __in  LPAPI_VERSION AppVersion
# );
# ===============================================================================
def ImagehlpApiVersionEx(MajorVersion, MinorVersion, Revision):
    _ImagehlpApiVersionEx = windll.dbghelp.ImagehlpApiVersionEx
    _ImagehlpApiVersionEx.argtypes = [LPAPI_VERSION]
    _ImagehlpApiVersionEx.restype = LPAPI_VERSION

    api_version = API_VERSION(MajorVersion, MinorVersion, Revision, 0)

    ret_api_version = _ImagehlpApiVersionEx(byref(api_version))

    return ret_api_version.contents


# ===============================================================================
# typedef enum {
#     AddrMode1616,
#     AddrMode1632,
#     AddrModeReal,
#     AddrModeFlat
# } ADDRESS_MODE;
# ===============================================================================
AddrMode1616 = 0
AddrMode1632 = 1
AddrModeReal = 2
AddrModeFlat = 3

ADDRESS_MODE = DWORD  # needed for the size of an ADDRESS_MODE (see ADDRESS64)


# ===============================================================================
# typedef struct _tagADDRESS64 {
#  DWORD64      Offset;
#  WORD         Segment;
#  ADDRESS_MODE Mode;
# } ADDRESS64, *LPADDRESS64;
# ===============================================================================
class ADDRESS64(Structure):
    _fields_ = [
        ("Offset", DWORD64),
        ("Segment", WORD),
        ("Mode", ADDRESS_MODE),  # it's a member of the ADDRESS_MODE enum.
    ]


LPADDRESS64 = POINTER(ADDRESS64)


# ===============================================================================
# typedef struct _KDHELP64 {
#    DWORD64   Thread;
#    DWORD   ThCallbackStack;
#    DWORD   ThCallbackBStore;
#    DWORD   NextCallback;
#    DWORD   FramePointer;
#    DWORD64   KiCallUserMode;
#    DWORD64   KeUserCallbackDispatcher;
#    DWORD64   SystemRangeStart;
#    DWORD64   KiUserExceptionDispatcher;
#    DWORD64   StackBase;
#    DWORD64   StackLimit;
#    DWORD64   Reserved[5];
# } KDHELP64, *PKDHELP64;
# ===============================================================================
class KDHELP64(Structure):
    _fields_ = [
        ("Thread", DWORD64),
        ("ThCallbackStack", DWORD),
        ("ThCallbackBStore", DWORD),
        ("NextCallback", DWORD),
        ("FramePointer", DWORD),
        ("KiCallUserMode", DWORD64),
        ("KeUserCallbackDispatcher", DWORD64),
        ("SystemRangeStart", DWORD64),
        ("KiUserExceptionDispatcher", DWORD64),
        ("StackBase", DWORD64),
        ("StackLimit", DWORD64),
        ("Reserved", DWORD64 * 5),
    ]


PKDHELP64 = POINTER(KDHELP64)


# ===============================================================================
# typedef struct _tagSTACKFRAME64 {
#  ADDRESS64 AddrPC;
#  ADDRESS64 AddrReturn;
#  ADDRESS64 AddrFrame;
#  ADDRESS64 AddrStack;
#  ADDRESS64 AddrBStore;
#  PVOID     FuncTableEntry;
#  DWORD64   Params[4];
#  BOOL      Far;
#  BOOL      Virtual;
#  DWORD64   Reserved[3];
#  KDHELP64  KdHelp;
# } STACKFRAME64, *LPSTACKFRAME64;
# ===============================================================================
class STACKFRAME64(Structure):
    _fields_ = [
        ("AddrPC", ADDRESS64),
        ("AddrReturn", ADDRESS64),
        ("AddrFrame", ADDRESS64),
        ("AddrStack", ADDRESS64),
        ("AddrBStore", ADDRESS64),
        ("FuncTableEntry", PVOID),
        ("Params", DWORD64 * 4),
        ("Far", BOOL),
        ("Virtual", BOOL),
        ("Reserved", DWORD64 * 3),
        ("KdHelp", KDHELP64),
    ]


LPSTACKFRAME64 = POINTER(STACKFRAME64)

# ===============================================================================
# BOOL CALLBACK ReadProcessMemoryProc64(
#  __in   HANDLE hProcess,
#  __in   DWORD64 lpBaseAddress,
#  __out  PVOID lpBuffer,
#  __in   DWORD nSize,
#  __out  LPDWORD lpNumberOfBytesRead
# );
# ===============================================================================
PREAD_PROCESS_MEMORY_ROUTINE64 = WINFUNCTYPE(
    BOOL, HANDLE, DWORD64, PVOID, DWORD, LPDWORD
)

# ===============================================================================
# PVOID CALLBACK FunctionTableAccessProc64(
#  __in  HANDLE hProcess,
#  __in  DWORD64 AddrBase
# );
# ===============================================================================
PFUNCTION_TABLE_ACCESS_ROUTINE64 = WINFUNCTYPE(PVOID, HANDLE, DWORD64)

# ===============================================================================
# DWORD64 CALLBACK GetModuleBaseProc64(
#  __in  HANDLE hProcess,
#  __in  DWORD64 Address
# );
# ===============================================================================
PGET_MODULE_BASE_ROUTINE64 = WINFUNCTYPE(DWORD64, HANDLE, DWORD64)

# ===============================================================================
# DWORD64 CALLBACK GetModuleBaseProc64(
#  __in  HANDLE hProcess,
#  __in  DWORD64 Address
# );
# ===============================================================================
PTRANSLATE_ADDRESS_ROUTINE64 = WINFUNCTYPE(DWORD64, HANDLE, DWORD64)

# Valid machine types for StackWalk64 function
IMAGE_FILE_MACHINE_I386 = 0x014C  # Intel x86
IMAGE_FILE_MACHINE_IA64 = 0x0200  # Intel Itanium Processor Family (IPF)
IMAGE_FILE_MACHINE_AMD64 = 0x8664  # x64 (AMD64 or EM64T)


# ===============================================================================
# BOOL WINAPI StackWalk64(
#  __in      DWORD MachineType,
#  __in      HANDLE hProcess,
#  __in      HANDLE hThread,
#  __inout   LPSTACKFRAME64 StackFrame,
#  __inout   PVOID ContextRecord,
#  __in_opt  PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
#  __in_opt  PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
#  __in_opt  PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
#  __in_opt  PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress
# );
# ===============================================================================
def StackWalk64(
    MachineType,
    hProcess,
    hThread,
    StackFrame,
    ContextRecord,
    ReadMemoryRoutine=None,
    FunctionTableAccessRoutine=None,
    GetModuleBaseRoutine=None,
    TranslateAddress=None,
):
    _StackWalk64 = windll.dbghelp.StackWalk64
    _StackWalk64.argtypes = [
        DWORD,
        HANDLE,
        HANDLE,
        LPSTACKFRAME64,
        PVOID,
        PREAD_PROCESS_MEMORY_ROUTINE64,
        PFUNCTION_TABLE_ACCESS_ROUTINE64,
        PGET_MODULE_BASE_ROUTINE64,
        PTRANSLATE_ADDRESS_ROUTINE64,
    ]
    _StackWalk64.restype = bool

    pReadMemoryRoutine = None
    if ReadMemoryRoutine:
        pReadMemoryRoutine = PREAD_PROCESS_MEMORY_ROUTINE64(ReadMemoryRoutine)
    else:
        pReadMemoryRoutine = ctypes.cast(None, PREAD_PROCESS_MEMORY_ROUTINE64)

    pFunctionTableAccessRoutine = None
    if FunctionTableAccessRoutine:
        pFunctionTableAccessRoutine = PFUNCTION_TABLE_ACCESS_ROUTINE64(
            FunctionTableAccessRoutine
        )
    else:
        pFunctionTableAccessRoutine = ctypes.cast(
            None, PFUNCTION_TABLE_ACCESS_ROUTINE64
        )

    pGetModuleBaseRoutine = None
    if GetModuleBaseRoutine:
        pGetModuleBaseRoutine = PGET_MODULE_BASE_ROUTINE64(GetModuleBaseRoutine)
    else:
        pGetModuleBaseRoutine = ctypes.cast(None, PGET_MODULE_BASE_ROUTINE64)

    pTranslateAddress = None
    if TranslateAddress:
        pTranslateAddress = PTRANSLATE_ADDRESS_ROUTINE64(TranslateAddress)
    else:
        pTranslateAddress = ctypes.cast(None, PTRANSLATE_ADDRESS_ROUTINE64)

    if ContextRecord is None:
        raise ValueError("ContextRecord cannot be None")
    pContextRecord = ctypes.c_void_p(ctypes.addressof(ContextRecord))

    # this function *DOESN'T* set last error [GetLastError()] properly most of the time.
    ret = _StackWalk64(
        MachineType,
        hProcess,
        hThread,
        byref(StackFrame),
        pContextRecord,
        pReadMemoryRoutine,
        pFunctionTableAccessRoutine,
        pGetModuleBaseRoutine,
        pTranslateAddress,
    )

    return ret


# ==============================================================================
# This calculates the list of exported symbols.
_all = set(vars().keys()).difference(_all)
__all__ = [_x for _x in _all if not _x.startswith("_")]
__all__.sort()
# ==============================================================================
