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
Debug helper API.
"""

__revision__ = "$Id$"

from kernel import *

#--- Constants ----------------------------------------------------------------

# Minidump types
MiniDumpNormal                           = 0x00000000
MiniDumpWithDataSegs                     = 0x00000001
MiniDumpWithFullMemory                   = 0x00000002
MiniDumpWithHandleData                   = 0x00000004
MiniDumpFilterMemory                     = 0x00000008
MiniDumpScanMemory                       = 0x00000010
MiniDumpWithUnloadedModules              = 0x00000020
MiniDumpWithIndirectlyReferencedMemory   = 0x00000040
MiniDumpFilterModulePaths                = 0x00000080
MiniDumpWithProcessThreadData            = 0x00000100
MiniDumpWithPrivateReadWriteMemory       = 0x00000200
MiniDumpWithoutOptionalData              = 0x00000400
MiniDumpWithFullMemoryInfo               = 0x00000800
MiniDumpWithThreadInfo                   = 0x00001000
MiniDumpWithCodeSegs                     = 0x00002000

# Minidump handle types
MiniHandleObjectInformationNone = 0
MiniThreadInformation1          = 1
MiniMutantInformation1          = 2
MiniMutantInformation2          = 3
MiniProcessInformation1         = 4
MiniProcessInformation2         = 5

# Minidump module write flags
ModuleWriteModule          = 0x0001
ModuleWriteDataSeg         = 0x0002
ModuleWriteMiscRecord      = 0x0004
ModuleWriteCvRecord        = 0x0008
ModuleReferencedByMemory   = 0x0010
ModuleWriteTlsData         = 0x0020
ModuleWriteCodeSegs        = 0x0040

# Minidump thread write flags
ThreadWriteThread              = 0x0001
ThreadWriteStack               = 0x0002
ThreadWriteContext             = 0x0004
ThreadWriteBackingStore        = 0x0008
ThreadWriteInstructionWindow   = 0x0010
ThreadWriteThreadData          = 0x0020
ThreadWriteThreadInfo          = 0x0040

# Minidump stream types
UnusedStream                = 0
ReservedStream0             = 1
ReservedStream1             = 2
ThreadListStream            = 3
ModuleListStream            = 4
MemoryListStream            = 5
ExceptionStream             = 6
SystemInfoStream            = 7
ThreadExListStream          = 8
Memory64ListStream          = 9
CommentStreamA              = 10
CommentStreamW              = 11
HandleDataStream            = 12
FunctionTableStream         = 13
UnloadedModuleListStream    = 14
MiscInfoStream              = 15
MemoryInfoListStream        = 16
ThreadInfoListStream        = 17
HandleOperationListStream   = 18
LastReservedStream          = 0xffff

# Minidump callback types
ModuleCallback                  = 0
ThreadCallback                  = 1
ThreadExCallback                = 2
IncludeThreadCallback           = 3
IncludeModuleCallback           = 4
MemoryCallback                  = 5
CancelCallback                  = 6
WriteKernelMinidumpCallback     = 7
KernelMinidumpStatusCallback    = 8
RemoveMemoryCallback            = 9
IncludeVmRegionCallback         = 10
IoStartCallback                 = 11
IoWriteAllCallback              = 12
IoFinishCallback                = 13
ReadMemoryFailureCallback       = 14
SecondaryFlagsCallback          = 15

# Secondary flags for minidumps
MiniSecondaryWithoutPowerInfo   = 0x00000001

# Misc info flags
MINIDUMP_MISC1_PROCESS_ID           = 0x00000001
MINIDUMP_MISC1_PROCESS_TIMES        = 0x00000002
MINIDUMP_MISC1_PROCESSOR_POWER_INFO = 0x00000004

TI_GET_SYMTAG                   = 0
TI_GET_SYMNAME                  = 1
TI_GET_LENGTH                   = 2
TI_GET_TYPE                     = 3
TI_GET_TYPEID                   = 4
TI_GET_BASETYPE                 = 5
TI_GET_ARRAYINDEXTYPEID         = 6
TI_FINDCHILDREN                 = 7
TI_GET_DATAKIND                 = 8
TI_GET_ADDRESSOFFSET            = 9
TI_GET_OFFSET                   = 10
TI_GET_VALUE                    = 11
TI_GET_COUNT                    = 12
TI_GET_CHILDRENCOUNT            = 13
TI_GET_BITPOSITION              = 14
TI_GET_VIRTUALBASECLASS         = 15
TI_GET_VIRTUALTABLESHAPEID      = 16
TI_GET_VIRTUALBASEPOINTEROFFSET = 17
TI_GET_CLASSPARENTID            = 18
TI_GET_NESTED                   = 19
TI_GET_SYMINDEX                 = 20
TI_GET_LEXICALPARENT            = 21
TI_GET_ADDRESS                  = 22
TI_GET_THISADJUST               = 23
TI_GET_UDTKIND                  = 24
TI_IS_EQUIV_TO                  = 25
TI_GET_CALLING_CONVENTION       = 26
TI_IS_CLOSE_EQUIV_TO            = 27
TI_GTIEX_REQS_VALID             = 28
TI_GET_VIRTUALBASEOFFSET        = 29
TI_GET_VIRTUALBASEDISPINDEX     = 30
TI_GET_IS_REFERENCE             = 31
TI_GET_INDIRECTVIRTUALBASECLASS = 32

#--- IMAGEHLP_MODULE structure and related ------------------------------------

SYMOPT_ALLOW_ABSOLUTE_SYMBOLS       = 0x00000800
SYMOPT_ALLOW_ZERO_ADDRESS           = 0x01000000
SYMOPT_AUTO_PUBLICS                 = 0x00010000
SYMOPT_CASE_INSENSITIVE             = 0x00000001
SYMOPT_DEBUG                        = 0x80000000
SYMOPT_DEFERRED_LOADS               = 0x00000004
SYMOPT_DISABLE_SYMSRV_AUTODETECT    = 0x02000000
SYMOPT_EXACT_SYMBOLS                = 0x00000400
SYMOPT_FAIL_CRITICAL_ERRORS         = 0x00000200
SYMOPT_FAVOR_COMPRESSED             = 0x00800000
SYMOPT_FLAT_DIRECTORY               = 0x00400000
SYMOPT_IGNORE_CVREC                 = 0x00000080
SYMOPT_IGNORE_IMAGEDIR              = 0x00200000
SYMOPT_IGNORE_NT_SYMPATH            = 0x00001000
SYMOPT_INCLUDE_32BIT_MODULES        = 0x00002000
SYMOPT_LOAD_ANYTHING                = 0x00000040
SYMOPT_LOAD_LINES                   = 0x00000010
SYMOPT_NO_CPP                       = 0x00000008
SYMOPT_NO_IMAGE_SEARCH              = 0x00020000
SYMOPT_NO_PROMPTS                   = 0x00080000
SYMOPT_NO_PUBLICS                   = 0x00008000
SYMOPT_NO_UNQUALIFIED_LOADS         = 0x00000100
SYMOPT_OVERWRITE                    = 0x00100000
SYMOPT_PUBLICS_ONLY                 = 0x00004000
SYMOPT_SECURE                       = 0x00040000
SYMOPT_UNDNAME                      = 0x00000002

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
SymNone     = 0
SymCoff     = 1
SymCv       = 2
SymPdb      = 3
SymExport   = 4
SymDeferred = 5
SymSym      = 6
SymDia      = 7
SymVirtual  = 8
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

class IMAGEHLP_MODULE (ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
    ]

class IMAGEHLP_MODULE64 (ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      CHAR * 32),
        ("ImageName",       CHAR * 256),
        ("LoadedImageName", CHAR * 256),
        ("LoadedPdbName",   CHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          CHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]

class IMAGEHLP_MODULEW (ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      WCHAR * 32),
        ("ImageName",       WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
    ]

class IMAGEHLP_MODULEW64 (ctypes.Structure):
    _fields_ = [
        ("SizeOfStruct",    DWORD),
        ("BaseOfImage",     DWORD64),
        ("ImageSize",       DWORD),
        ("TimeDateStamp",   DWORD),
        ("CheckSum",        DWORD),
        ("NumSyms",         DWORD),
        ("SymType",         DWORD),         # SYM_TYPE
        ("ModuleName",      WCHAR * 32),
        ("ImageName",       WCHAR * 256),
        ("LoadedImageName", WCHAR * 256),
        ("LoadedPdbName",   WCHAR * 256),
        ("CVSig",           DWORD),
        ("CVData",          WCHAR * (MAX_PATH * 3)),
        ("PdbSig",          DWORD),
        ("PdbSig70",        GUID),
        ("PdbAge",          DWORD),
        ("PdbUnmatched",    BOOL),
        ("DbgUnmatched",    BOOL),
        ("LineNumbers",     BOOL),
        ("GlobalSymbols",   BOOL),
        ("TypeInfo",        BOOL),
        ("SourceIndexed",   BOOL),
        ("Publics",         BOOL),
    ]

#--- Minidump structures ------------------------------------------------------

# struct VS_FIXEDFILEINFO {
#   DWORD dwSignature;
#   DWORD dwStrucVersion;
#   DWORD dwFileVersionMS;
#   DWORD dwFileVersionLS;
#   DWORD dwProductVersionMS;
#   DWORD dwProductVersionLS;
#   DWORD dwFileFlagsMask;
#   DWORD dwFileFlags;
#   DWORD dwFileOS;
#   DWORD dwFileType;
#   DWORD dwFileSubtype;
#   DWORD dwFileDateMS;
#   DWORD dwFileDateLS;
# };
class VS_FIXEDFILEINFO (Structure):
    _fields_ = [
        ("dwSignature",             DWORD),     # 0xFEEF04BD
        ("dwStrucVersion",          DWORD),
        ("dwFileVersionMS",         DWORD),
        ("dwFileVersionLS",         DWORD),
        ("dwProductVersionMS",      DWORD),
        ("dwProductVersionLS",      DWORD),
        ("dwFileFlagsMask",         DWORD),
        ("dwFileFlags",             DWORD),
        ("dwFileOS",                DWORD),
        ("dwFileType",              DWORD),
        ("dwFileSubtype",           DWORD),
        ("dwFileDateMS",            DWORD),
        ("dwFileDateLS",            DWORD),
    ]

# typedef struct _MINIDUMP_STRING {
#   ULONG32 Length;
#   WCHAR   Buffer[];
# }MINIDUMP_STRING, *PMINIDUMP_STRING;
class MINIDUMP_STRING (Structure):
    _fields_ = [
        ("Length",      ULONG32),
        ("Buffer",      WCHAR * 1)
    ]

# typedef struct _MINIDUMP_MISC_INFO {
#   ULONG32 SizeOfInfo;
#   ULONG32 Flags1;
#   ULONG32 ProcessId;
#   ULONG32 ProcessCreateTime;
#   ULONG32 ProcessUserTime;
#   ULONG32 ProcessKernelTime;
# } MINIDUMP_MISC_INFO, *PMINIDUMP_MISC_INFO;
class MINIDUMP_MISC_INFO (Structure):
    _fields_ = [
        ("SizeOfInfo",                  ULONG32),
        ("Flags1",                      ULONG32),
        ("ProcessId",                   ULONG32),
        ("ProcessCreateTime",           ULONG32),
        ("ProcessUserTime",             ULONG32),
        ("ProcessKernelTime",           ULONG32),
    ]

# typedef struct _MINIDUMP_MISC_INFO_2 {
#   ULONG32 SizeOfInfo;
#   ULONG32 Flags1;
#   ULONG32 ProcessId;
#   ULONG32 ProcessCreateTime;
#   ULONG32 ProcessUserTime;
#   ULONG32 ProcessKernelTime;
#   ULONG32 ProcessorMaxMhz;
#   ULONG32 ProcessorCurrentMhz;
#   ULONG32 ProcessorMhzLimit;
#   ULONG32 ProcessorMaxIdleState;
#   ULONG32 ProcessorCurrentIdleState;
# } MINIDUMP_MISC_INFO_2, *PMINIDUMP_MISC_INFO_2;
class MINIDUMP_MISC_INFO_2 (Structure):
    _fields_ = [
        ("SizeOfInfo",                  ULONG32),
        ("Flags1",                      ULONG32),
        ("ProcessId",                   ULONG32),
        ("ProcessCreateTime",           ULONG32),
        ("ProcessUserTime",             ULONG32),
        ("ProcessKernelTime",           ULONG32),
        ("ProcessorMaxMhz",             ULONG32),
        ("ProcessorCurrentMhz",         ULONG32),
        ("ProcessorMhzLimit",           ULONG32),
        ("ProcessorMaxIdleState",       ULONG32),
        ("ProcessorCurrentIdleState",   ULONG32),
    ]

# typedef struct _MINIDUMP_LOCATION_DESCRIPTOR {
#   ULONG32 DataSize;
#   RVA     Rva;
# } MINIDUMP_LOCATION_DESCRIPTOR;
class MINIDUMP_LOCATION_DESCRIPTOR (Structure):
    _fields_ = [
        ("DataSize",  ULONG32),
        ("Rva",       RVA),
    ]

# typedef struct _MINIDUMP_LOCATION_DESCRIPTOR64 {
#   ULONG64 DataSize;
#   RVA64 Rva;
# } MINIDUMP_LOCATION_DESCRIPTOR64;
class MINIDUMP_LOCATION_DESCRIPTOR64 (Structure):
    _fields_ = [
        ("DataSize",  ULONG64),
        ("Rva",       RVA64),
    ]

# typedef struct _MINIDUMP_MEMORY_DESCRIPTOR {
#   ULONG64                      StartOfMemoryRange;
#   MINIDUMP_LOCATION_DESCRIPTOR Memory;
# } MINIDUMP_MEMORY_DESCRIPTOR, *PMINIDUMP_MEMORY_DESCRIPTOR;
class MINIDUMP_MEMORY_DESCRIPTOR (Structure):
    _fields_ = [
        ("StartOfMemoryRange",  ULONG64),
        ("Memory",              MINIDUMP_LOCATION_DESCRIPTOR),
    ]

# typedef struct _MINIDUMP_THREAD {
#   ULONG32                      ThreadId;
#   ULONG32                      SuspendCount;
#   ULONG32                      PriorityClass;
#   ULONG32                      Priority;
#   ULONG64                      Teb;
#   MINIDUMP_MEMORY_DESCRIPTOR   Stack;
#   MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
# } MINIDUMP_THREAD, *PMINIDUMP_THREAD;
class MINIDUMP_THREAD (Structure):
    _fields_ = [
        ("ThreadId",        ULONG32),
        ("SuspendCount",    ULONG32),
        ("PriorityClass",   ULONG32),
        ("Priority",        ULONG32),
        ("Teb",             ULONG64),
        ("Stack",           MINIDUMP_MEMORY_DESCRIPTOR),
        ("ThreadContext",   MINIDUMP_LOCATION_DESCRIPTOR),
    ]

# typedef struct _MINIDUMP_THREAD_EX {
#   ULONG32                      ThreadId;
#   ULONG32                      SuspendCount;
#   ULONG32                      PriorityClass;
#   ULONG32                      Priority;
#   ULONG64                      Teb;
#   MINIDUMP_MEMORY_DESCRIPTOR   Stack;
#   MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
#   MINIDUMP_MEMORY_DESCRIPTOR   BackingStore;
# }MINIDUMP_THREAD_EX, *PMINIDUMP_THREAD_EX;
class MINIDUMP_THREAD_EX (Structure):
    _fields_ = [
        ("ThreadId",        ULONG32),
        ("SuspendCount",    ULONG32),
        ("PriorityClass",   ULONG32),
        ("Priority",        ULONG32),
        ("Teb",             ULONG64),
        ("Stack",           MINIDUMP_MEMORY_DESCRIPTOR),
        ("ThreadContext",   MINIDUMP_LOCATION_DESCRIPTOR),
        ("BackingStore",    MINIDUMP_MEMORY_DESCRIPTOR),
    ]

# typedef struct _MINIDUMP_THREAD_LIST {
#   ULONG32         NumberOfThreads;
#   MINIDUMP_THREAD Threads[];
# } MINIDUMP_THREAD_LIST, *PMINIDUMP_THREAD_LIST;
class MINIDUMP_THREAD_LIST (Structure):
    _fields_ = [
        ("NumberOfThreads", ULONG32),
        ("Threads",         MINIDUMP_THREAD * 1),       # variable size array
    ]

# typedef struct _MINIDUMP_THREAD_EX_LIST {
#   ULONG32            NumberOfThreads;
#   MINIDUMP_THREAD_EX Threads[];
# }MINIDUMP_THREAD_EX_LIST, *PMINIDUMP_THREAD_EX_LIST;
class MINIDUMP_THREAD_EX_LIST (Structure):
    _fields_ = [
        ("NumberOfThreads", ULONG32),
        ("Threads",         MINIDUMP_THREAD_EX * 1),    # variable size array
    ]

# typedef struct _MINIDUMP_MEMORY_LIST {
#   ULONG32                    NumberOfMemoryRanges;
#   MINIDUMP_MEMORY_DESCRIPTOR MemoryRanges[];
# }MINIDUMP_MEMORY_LIST, *PMINIDUMP_MEMORY_LIST;
class MINIDUMP_MEMORY_LIST (Structure):
    _fields_ = [
        ("NumberOfMemoryRanges",  ULONG32),
        ("MemoryRanges",          MINIDUMP_MEMORY_DESCRIPTOR * 1),
    ]

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
# }MINIDUMP_MEMORY_INFO, *PMINIDUMP_MEMORY_INFO;
class MINIDUMP_MEMORY_INFO (Structure):
    _fields_ = [
        ("BaseAddress",         ULONG64),
        ("AllocationBase",      ULONG64),
        ("AllocationProtect",   ULONG32),
        ("__alignment1",        ULONG32),
        ("RegionSize",          ULONG64),
        ("State",               ULONG32),
        ("Protect",             ULONG32),
        ("Type",                ULONG32),
        ("__alignment2",        ULONG32),
    ]

# typedef struct _MINIDUMP_MEMORY_INFO_LIST {
#   ULONG   SizeOfHeader;
#   ULONG   SizeOfEntry;
#   ULONG64 NumberOfEntries;
# }MINIDUMP_MEMORY_INFO_LIST, *PMINIDUMP_MEMORY_INFO_LIST;
class MINIDUMP_MEMORY_INFO_LIST (Structure):
    _fields_ = [
        ("SizeOfHeader",        ULONG),
        ("SizeOfEntry",         ULONG),
        ("NumberOfEntries",     ULONG64),
    ]

# typedef struct _MINIDUMP_MODULE {
#   ULONG64                      BaseOfImage;
#   ULONG32                      SizeOfImage;
#   ULONG32                      CheckSum;
#   ULONG32                      TimeDateStamp;
#   RVA                          ModuleNameRva;
#   VS_FIXEDFILEINFO             VersionInfo;
#   MINIDUMP_LOCATION_DESCRIPTOR CvRecord;
#   MINIDUMP_LOCATION_DESCRIPTOR MiscRecord;
#   ULONG64                      Reserved0;
#   ULONG64                      Reserved1;
# }MINIDUMP_MODULE, *PMINIDUMP_MODULE;
class MINIDUMP_MODULE (Structure):
    _fields_ = [
        ("BaseOfImage",         ULONG64),
        ("SizeOfImage",         ULONG32),
        ("CheckSum",            ULONG32),
        ("ModuleNameRva",       ULONG32),
        ("ModuleNameRva",       RVA),
        ("VersionInfo",         VS_FIXEDFILEINFO),
        ("CvRecord",            MINIDUMP_LOCATION_DESCRIPTOR),
        ("MiscRecord",          MINIDUMP_LOCATION_DESCRIPTOR),
        ("Reserved0",           ULONG64),
        ("Reserved1",           ULONG64),
    ]

# typedef struct _MINIDUMP_MODULE_LIST {
#   ULONG32         NumberOfModules;
#   MINIDUMP_MODULE Modules[];
# }MINIDUMP_MODULE_LIST, *PMINIDUMP_MODULE_LIST;Members
class MINIDUMP_MODULE_LIST (Structure):
    _fields_ = [
        ("NumberOfModules",  ULONG32),
        ("Modules",          MINIDUMP_MODULE * 1),
    ]

# typedef struct _MINIDUMP_UNLOADED_MODULE {
#   ULONG64 BaseOfImage;
#   ULONG32 SizeOfImage;
#   ULONG32 CheckSum;
#   ULONG32 TimeDateStamp;
#   RVA     ModuleNameRva;
# }MINIDUMP_UNLOADED_MODULE, *PMINIDUMP_UNLOADED_MODULE;
class MINIDUMP_UNLOADED_MODULE (Structure):
    _fields_ = [
        ("BaseOfImage",             ULONG64),
        ("SizeOfImage",             ULONG32),
        ("CheckSum",                ULONG32),
        ("TimeDateStamp",           ULONG32),
        ("ModuleNameRva",           RVA),
    ]

# typedef struct _MINIDUMP_UNLOADED_MODULE_LIST {
#   ULONG32 SizeOfHeader;
#   ULONG32 SizeOfEntry;
#   ULONG32 NumberOfEntries;
# }MINIDUMP_UNLOADED_MODULE_LIST, *PMINIDUMP_UNLOADED_MODULE_LIST;
class MINIDUMP_UNLOADED_MODULE_LIST (Structure):
    _fields_ = [
        ("SizeOfHeader",            ULONG32),
        ("SizeOfEntry",             ULONG32),
        ("NumberOfEntries",         ULONG32),
    ]

# typedef struct _MINIDUMP_DIRECTORY {
#   ULONG32                      StreamType;
#   MINIDUMP_LOCATION_DESCRIPTOR Location;
# }MINIDUMP_DIRECTORY, *PMINIDUMP_DIRECTORY;
class MINIDUMP_DIRECTORY (Structure):
    _fields_ = [
        ("StreamType",          ULONG32),
        ("Location",            MINIDUMP_LOCATION_DESCRIPTOR),
    ]

# typedef struct _EXCEPTION_POINTERS {
#   PEXCEPTION_RECORD ExceptionRecord;
#   PCONTEXT          ContextRecord;
# } EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
class EXCEPTION_POINTERS (Structure):
    _fields_ = [
        ("ExceptionRecord", PEXCEPTION_RECORD),
        ("ContextRecord",   PCONTEXT),
    ]
PEXCEPTION_POINTERS = POINTER(EXCEPTION_POINTERS)

# typedef struct _MINIDUMP_EXCEPTION_INFORMATION {
#   DWORD               ThreadId;
#   PEXCEPTION_POINTERS ExceptionPointers;
#   BOOL                ClientPointers;
# } MINIDUMP_EXCEPTION_INFORMATION, *PMINIDUMP_EXCEPTION_INFORMATION;
class MINIDUMP_EXCEPTION_INFORMATION (Structure):
    _fields_ = [
        ("ThreadId",            DWORD),
        ("ExceptionPointers",   PEXCEPTION_POINTERS),
        ("ClientPointers",      BOOL),
    ]

PMINIDUMP_EXCEPTION_INFORMATION = POINTER(MINIDUMP_EXCEPTION_INFORMATION)

# typedef struct _MINIDUMP_EXCEPTION {
#   ULONG32 ExceptionCode;
#   ULONG32 ExceptionFlags;
#   ULONG64 ExceptionRecord;
#   ULONG64 ExceptionAddress;
#   ULONG32 NumberParameters;
#   ULONG32 __unusedAlignment;
#   ULONG64 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
# }MINIDUMP_EXCEPTION, *PMINIDUMP_EXCEPTION;
class MINIDUMP_EXCEPTION (Structure):
    _fields_ = [
        ("ExceptionCode",           ULONG32),
        ("ExceptionFlags",          ULONG32),
        ("ExceptionRecord",         ULONG64),
        ("ExceptionAddress",        ULONG64),
        ("NumberParameters",        ULONG32),
        ("__unusedAlignment",       ULONG32),
        ("ExceptionInformation",    ULONG64 * EXCEPTION_MAXIMUM_PARAMETERS),
    ]

# typedef struct MINIDUMP_EXCEPTION_STREAM {
#   ULONG32                      ThreadId;
#   ULONG32                      __alignment;
#   MINIDUMP_EXCEPTION           ExceptionRecord;
#   MINIDUMP_LOCATION_DESCRIPTOR ThreadContext;
# }MINIDUMP_EXCEPTION_STREAM, *PMINIDUMP_EXCEPTION_STREAM;
class MINIDUMP_EXCEPTION_STREAM (Structure):
    _fields_ = [
        ("ThreadId",            ULONG32),
        ("__alignment",         ULONG32),
        ("ExceptionRecord",     MINIDUMP_EXCEPTION),
        ("ThreadContext",       MINIDUMP_LOCATION_DESCRIPTOR),
    ]

# typedef struct _MINIDUMP_FUNCTION_TABLE_DESCRIPTOR {
#   ULONG64 MinimumAddress;
#   ULONG64 MaximumAddress;
#   ULONG64 BaseAddress;
#   ULONG32 EntryCount;
#   ULONG32 SizeOfAlignPad;
# }MINIDUMP_FUNCTION_TABLE_DESCRIPTOR, *PMINIDUMP_FUNCTION_TABLE_DESCRIPTOR;
class MINIDUMP_FUNCTION_TABLE_DESCRIPTOR (Structure):
    _fields_ = [
        ("MinimumAddress",      ULONG64),
        ("MaximumAddress",      ULONG64),
        ("BaseAddress",         ULONG64),
        ("EntryCount",          ULONG32),
        ("SizeOfAlignPad",      ULONG32),
    ]

# typedef struct _MINIDUMP_FUNCTION_TABLE_STREAM {
#   ULONG32 SizeOfHeader;
#   ULONG32 SizeOfDescriptor;
#   ULONG32 SizeOfNativeDescriptor;
#   ULONG32 SizeOfFunctionEntry;
#   ULONG32 NumberOfDescriptors;
#   ULONG32 SizeOfAlignPad;
# }MINIDUMP_FUNCTION_TABLE_STREAM, *PMINIDUMP_FUNCTION_TABLE_STREAM;
class MINIDUMP_FUNCTION_TABLE_STREAM (Structure):
    _fields_ = [
        ("SizeOfHeader",                ULONG32),
        ("SizeOfDescriptor",            ULONG32),
        ("SizeOfNativeDescriptor",      ULONG32),
        ("SizeOfFunctionEntry",         ULONG32),
        ("NumberOfDescriptors",         ULONG32),
        ("SizeOfAlignPad",              ULONG32),
    ]

# typedef struct _MINIDUMP_HANDLE_DATA_STREAM {
#   ULONG32 SizeOfHeader;
#   ULONG32 SizeOfDescriptor;
#   ULONG32 NumberOfDescriptors;
#   ULONG32 Reserved;
# }MINIDUMP_HANDLE_DATA_STREAM, *PMINIDUMP_HANDLE_DATA_STREAM;
class MINIDUMP_HANDLE_DATA_STREAM (Structure):
    _fields_ = [
        ("SizeOfHeader",                ULONG32),
        ("SizeOfDescriptor",            ULONG32),
        ("NumberOfDescriptors",         ULONG32),
        ("Reserved",                    ULONG32),
    ]

# typedef struct _MINIDUMP_HANDLE_DESCRIPTOR {
#   ULONG64 Handle;
#   RVA     TypeNameRva;
#   RVA     ObjectNameRva;
#   ULONG32 Attributes;
#   ULONG32 GrantedAccess;
#   ULONG32 HandleCount;
#   ULONG32 PointerCount;
# }MINIDUMP_HANDLE_DESCRIPTOR, *PMINIDUMP_HANDLE_DESCRIPTOR;Members
class MINIDUMP_HANDLE_DESCRIPTOR (Structure):
    _fields_ = [
        ("Handle",              ULONG64),
        ("TypeNameRva",         RVA),
        ("ObjectNameRva",       RVA),
        ("Attributes",          ULONG32),
        ("GrantedAccess",       ULONG32),
        ("HandleCount",         ULONG32),
        ("PointerCount",        ULONG32),
    ]

# typedef struct _MINIDUMP_HANDLE_DESCRIPTOR_2 {
#   ULONG64 Handle;
#   RVA     TypeNameRva;
#   RVA     ObjectNameRva;
#   ULONG32 Attributes;
#   ULONG32 GrantedAccess;
#   ULONG32 HandleCount;
#   ULONG32 PointerCount;
#   RVA     ObjectInfoRva;
#   ULONG32 Reserved0;
# }MINIDUMP_HANDLE_DESCRIPTOR_2, *PMINIDUMP_HANDLE_DESCRIPTOR_2;
class MINIDUMP_HANDLE_DESCRIPTOR_2 (Structure):
    _fields_ = [
        ("Handle",              ULONG64),
        ("TypeNameRva",         RVA),
        ("ObjectNameRva",       RVA),
        ("Attributes",          ULONG32),
        ("GrantedAccess",       ULONG32),
        ("HandleCount",         ULONG32),
        ("PointerCount",        ULONG32),
        ("ObjectInfoRva",       RVA),
        ("Reserved0",           ULONG32),
    ]

# typedef struct _MINIDUMP_HANDLE_OBJECT_INFORMATION {
#   RVA     NextInfoRva;
#   ULONG32 InfoType;
#   ULONG32 SizeOfInfo;
# }MINIDUMP_HANDLE_OBJECT_INFORMATION;
class MINIDUMP_HANDLE_OBJECT_INFORMATION (Structure):
    _fields_ = [
        ("NextInfoRva",     RVA),
        ("InfoType",        ULONG32),
        ("SizeOfInfo",      ULONG32),
    ]

# typedef struct _MINIDUMP_HANDLE_OPERATION_LIST {
#   ULONG32 SizeOfHeader;
#   ULONG32 SizeOfEntry;
#   ULONG32 NumberOfEntries;
#   ULONG32 Reserved;
# }MINIDUMP_HANDLE_OPERATION_LIST, *PMINIDUMP_HANDLE_OPERATION_LIST;
class MINIDUMP_HANDLE_OBJECT_INFORMATION (Structure):
    _fields_ = [
        ("SizeOfHeader",        ULONG32),
        ("SizeOfEntry",         ULONG32),
        ("NumberOfEntries",     ULONG32),
        ("Reserved",            ULONG32),
    ]

# typedef struct _MINIDUMP_HEADER {
#   ULONG32 Signature;
#   ULONG32 Version;
#   ULONG32 NumberOfStreams;
#   RVA     StreamDirectoryRva;
#   ULONG32 CheckSum;
#   union {
#     ULONG32 Reserved;
#     ULONG32 TimeDateStamp;
#   } ;
#   ULONG64 Flags;
# }MINIDUMP_HEADER, *PMINIDUMP_HEADER;
class _MINIDUMP_HEADER_UNION (Union):
    _fields_ = [
        ("Reserved",        ULONG32),
        ("TimeDateStamp",   ULONG32),
    ]
class MINIDUMP_HEADER (Structure):
    _fields_ = [
        ("Signature",           ULONG32),
        ("Version",             ULONG32),
        ("NumberOfStreams",     ULONG32),
        ("StreamDirectoryRva",  RVA),
        ("CheckSum",            ULONG32),
        ("u",                   _MINIDUMP_HEADER_UNION),
        ("Flags",               ULONG64),
    ]

# typedef struct _MINIDUMP_SYSTEM_INFO {
#   USHORT  ProcessorArchitecture;
#   USHORT  ProcessorLevel;
#   USHORT  ProcessorRevision;
#   union {
#     USHORT Reserved0;
#     struct {
#       UCHAR NumberOfProcessors;
#       UCHAR ProductType;
#     } ;
#   } ;
#   ULONG32 MajorVersion;
#   ULONG32 MinorVersion;
#   ULONG32 BuildNumber;
#   ULONG32 PlatformId;
#   RVA     CSDVersionRva;
#   union {
#     ULONG32 Reserved1;
#     struct {
#       USHORT SuiteMask;
#       USHORT Reserved2;
#     } ;
#   } ;
#   union {
#     struct {
#       ULONG32 VendorId[3];
#       ULONG32 VersionInformation;
#       ULONG32 FeatureInformation;
#       ULONG32 AMDExtendedCpuFeatures;
#     } X86CpuInfo;
#     struct {
#       ULONG64 ProcessorFeatures[2];
#     } OtherCpuInfo;
#   } Cpu;
# }MINIDUMP_SYSTEM_INFO, *PMINIDUMP_SYSTEM_INFO;
class _MINIDUMP_SYSTEM_INFO_UNION_1_STRUCT (Structure):
    _fields_ = [
        ("NumberOfProcessors",  UCHAR),
        ("ProductType",         UCHAR),
    ]
class _MINIDUMP_SYSTEM_INFO_UNION_1 (Union):
    _fields_ = [
        ("Reserved1",           ULONG32),
        ("s",                   _MINIDUMP_SYSTEM_INFO_UNION_1_STRUCT),
    ]
class _MINIDUMP_SYSTEM_INFO_UNION_2_STRUCT (Structure):
    _fields_ = [
        ("SuiteMask",           UCHAR),
        ("Reserved2",           UCHAR),
    ]
class _MINIDUMP_SYSTEM_INFO_UNION_2 (Union):
    _fields_ = [
        ("Reserved0",           ULONG32),
        ("s",                   _MINIDUMP_SYSTEM_INFO_UNION_2_STRUCT),
    ]
class _MINIDUMP_SYSTEM_INFO_UNION_3_STRUCT_1 (Structure):
    _fields_ = [
        ("VendorId",                UCHAR * 3),
        ("VersionInformation",      UCHAR),
        ("FeatureInformation",      UCHAR),
        ("AMDExtendedCpuFeatures",  UCHAR),
    ]
class _MINIDUMP_SYSTEM_INFO_UNION_3_STRUCT_2 (Structure):
    _fields_ = [
        ("ProcessorFeatures",       ULONG64),
    ]
class _MINIDUMP_SYSTEM_INFO_UNION_3 (Union):
    _fields_ = [
        ("X86CpuInfo",              _MINIDUMP_SYSTEM_INFO_UNION_3_STRUCT_1),
        ("OtherCpuInfo",            _MINIDUMP_SYSTEM_INFO_UNION_3_STRUCT_2),
    ]
class MINIDUMP_SYSTEM_INFO (Structure):
    _fields_ = [
        ("ProcessorArchitecture",   USHORT),
        ("ProcessorLevel",          USHORT),
        ("ProcessorRevision",       USHORT),
        ("u1",                      _MINIDUMP_SYSTEM_INFO_UNION_1),
        ("MajorVersion",            ULONG32),
        ("MinorVersion",            ULONG32),
        ("BuildNumber",             ULONG32),
        ("PlatformId",              ULONG32),
        ("CSDVersionRva",           RVA),
        ("u2",                      _MINIDUMP_SYSTEM_INFO_UNION_2),
        ("Cpu",                     _MINIDUMP_SYSTEM_INFO_UNION_3),
    ]

# typedef struct _MINIDUMP_USER_STREAM {
#   ULONG32 Type;
#   ULONG   BufferSize;
#   PVOID   Buffer;
# } MINIDUMP_USER_STREAM, *PMINIDUMP_USER_STREAM;
class MINIDUMP_USER_STREAM (Structure):
    _fields_ = [
        ("Type",        ULONG32),
        ("BufferSize",  ULONG),
        ("Buffer",      PVOID),
    ]

PMINIDUMP_USER_STREAM = POINTER(MINIDUMP_USER_STREAM)

# typedef struct _MINIDUMP_USER_STREAM_INFORMATION {
#   ULONG                 UserStreamCount;
#   PMINIDUMP_USER_STREAM UserStreamArray;
# } MINIDUMP_USER_STREAM_INFORMATION, *PMINIDUMP_USER_STREAM_INFORMATION;
class MINIDUMP_USER_STREAM_INFORMATION (Structure):
    _fields_ = [
        ("UserStreamCount",     ULONG),
        ("UserStreamArray",     PMINIDUMP_USER_STREAM),
    ]

# typedef struct _MINIDUMP_THREAD_CALLBACK {
#   ULONG   ThreadId;
#   HANDLE  ThreadHandle;
#   CONTEXT Context;
#   ULONG   SizeOfContext;
#   ULONG64 StackBase;
#   ULONG64 StackEnd;
# } MINIDUMP_THREAD_CALLBACK, *PMINIDUMP_THREAD_CALLBACK;
class MINIDUMP_THREAD_CALLBACK (Structure):
    _fields_ = [
        ("ThreadId",        ULONG),
        ("ThreadHandle",    HANDLE),
        ("Context",         CONTEXT),
        ("SizeOfContext",   ULONG),
        ("StackBase",       ULONG64),
        ("StackEnd",        ULONG64),
    ]

# typedef struct _MINIDUMP_THREAD_EX_CALLBACK {
#   ULONG   ThreadId;
#   HANDLE  ThreadHandle;
#   CONTEXT Context;
#   ULONG   SizeOfContext;
#   ULONG64 StackBase;
#   ULONG64 StackEnd;
#   ULONG64 BackingStoreBase;
#   ULONG64 BackingStoreEnd;
# } MINIDUMP_THREAD_EX_CALLBACK, *PMINIDUMP_THREAD_EX_CALLBACK;
class MINIDUMP_THREAD_EX_CALLBACK (Structure):
    _fields_ = [
        ("ThreadId",                ULONG),
        ("ThreadHandle",            HANDLE),
        ("Context",                 CONTEXT),
        ("SizeOfContext",           ULONG),
        ("StackBase",               ULONG64),
        ("StackEnd",                ULONG64),
        ("BackingStoreBase",        ULONG64),
        ("BackingStoreEnd",         ULONG64),
    ]

# typedef struct _MINIDUMP_MODULE_CALLBACK {
#   PWCHAR           FullPath;
#   ULONG64          BaseOfImage;
#   ULONG            SizeOfImage;
#   ULONG            CheckSum;
#   ULONG            TimeDateStamp;
#   VS_FIXEDFILEINFO VersionInfo;
#   PVOID            CvRecord;
#   ULONG            SizeOfCvRecord;
#   PVOID            MiscRecord;
#   ULONG            SizeOfMiscRecord;
# } MINIDUMP_MODULE_CALLBACK, *PMINIDUMP_MODULE_CALLBACK;
class MINIDUMP_MODULE_CALLBACK (Structure):
    _fields_ = [
        ("FullPath",                PWCHAR),
        ("BaseOfImage",             ULONG64),
        ("SizeOfImage",             ULONG),
        ("CheckSum",                ULONG),
        ("TimeDateStamp",           ULONG),
        ("VersionInfo",             VS_FIXEDFILEINFO),
        ("CvRecord",                PVOID),
        ("SizeOfCvRecord",          ULONG),
        ("MiscRecord",              PVOID),
        ("SizeOfMiscRecord",        ULONG),
    ]

# typedef struct _MINIDUMP_INCLUDE_THREAD_CALLBACK {
#   ULONG ThreadId;
# } MINIDUMP_INCLUDE_THREAD_CALLBACK, *PMINIDUMP_INCLUDE_THREAD_CALLBACK;
class MINIDUMP_INCLUDE_THREAD_CALLBACK (Structure):
    _fields_ = [
        ("ThreadId",                ULONG),
    ]

# typedef struct _MINIDUMP_INCLUDE_MODULE_CALLBACK {
#   ULONG64 BaseOfImage;
# } MINIDUMP_INCLUDE_MODULE_CALLBACK, *PMINIDUMP_INCLUDE_MODULE_CALLBACK;
class MINIDUMP_INCLUDE_MODULE_CALLBACK (Structure):
    _fields_ = [
        ("BaseOfImage",             ULONG64),
    ]

# typedef struct _MINIDUMP_IO_CALLBACK {
#   HANDLE  Handle;
#   ULONG64 Offset;
#   PVOID   Buffer;
#   ULONG   BufferBytes;
# } MINIDUMP_IO_CALLBACK, *PMINIDUMP_IO_CALLBACK;
class MINIDUMP_IO_CALLBACK (Structure):
    _fields_ = [
        ("Handle",              HANDLE),
        ("Offset",              ULONG64),
        ("Buffer",              PVOID),
        ("BufferBytes",         ULONG),
    ]

# typedef struct _MINIDUMP_READ_MEMORY_FAILURE_CALLBACK {
#   ULONG64 Offset;
#   ULONG   Bytes;
#   HRESULT FailureStatus;
# } MINIDUMP_READ_MEMORY_FAILURE_CALLBACK, *PMINIDUMP_READ_MEMORY_FAILURE_CALLBACK;
class MINIDUMP_READ_MEMORY_FAILURE_CALLBACK (Structure):
    _fields_ = [
        ("Offset",          ULONG64),
        ("Bytes",           ULONG),
        ("FailureStatus",   HRESULT),
    ]

# typedef struct _MINIDUMP_CALLBACK_OUTPUT {
#   union {
#     ULONG ModuleWriteFlags;
#     ULONG ThreadWriteFlags;
#     ULONG SecondaryFlags;
#     struct {
#       ULONG64 MemoryBase;
#       ULONG MemorySize;
#     } ;
#     struct {
#       BOOL CheckCancel;
#       BOOL Cancel;
#     } ;
#     HANDLE Handle;
#   } ;
#   struct {
#     MINIDUMP_MEMORY_INFO VmRegion;
#     BOOL Continue;
#   } ;
#   HRESULT Status;
# } MINIDUMP_CALLBACK_OUTPUT, *PMINIDUMP_CALLBACK_OUTPUT;
class _MINIDUMP_CALLBACK_OUTPUT_UNION_STRUCT_1 (Structure):
    _fields_ = [
        ("MemoryBase",      ULONG64),
        ("MemorySize",      ULONG),
    ]
class _MINIDUMP_CALLBACK_OUTPUT_UNION_STRUCT_2 (Structure):
    _fields_ = [
        ("CheckCancel",     BOOL),
        ("Cancel",          BOOL),
    ]
class _MINIDUMP_CALLBACK_OUTPUT_UNION (Union):
    _fields_ = [
        ("ModuleWriteFlags",     ULONG),
        ("ThreadWriteFlags",     ULONG),
        ("SecondaryFlags",       ULONG),
        ("s1",                  _MINIDUMP_CALLBACK_OUTPUT_UNION_STRUCT_1),
        ("s2",                  _MINIDUMP_CALLBACK_OUTPUT_UNION_STRUCT_2),
        ("Handle",              HANDLE),
    ]
class _MINIDUMP_CALLBACK_OUTPUT_STRUCT (Structure):
    _fields_ = [
        ("VmRegion",        MINIDUMP_MEMORY_INFO),
        ("Continue",        BOOL),
    ]
class MINIDUMP_CALLBACK_OUTPUT (Structure):
    _fields_ = [
        ("u",       _MINIDUMP_CALLBACK_OUTPUT_UNION),
        ("s",       _MINIDUMP_CALLBACK_OUTPUT_STRUCT),
        ("Status",  HRESULT),
    ]
PMINIDUMP_CALLBACK_OUTPUT = POINTER(MINIDUMP_CALLBACK_OUTPUT)

# typedef struct _MINIDUMP_CALLBACK_INPUT {
#   ULONG  ProcessId;
#   HANDLE ProcessHandle;
#   ULONG  CallbackType;
#   union {
#     HRESULT Status;
#     MINIDUMP_THREAD_CALLBACK Thread;
#     MINIDUMP_THREAD_EX_CALLBACK ThreadEx;
#     MINIDUMP_MODULE_CALLBACK Module;
#     MINIDUMP_INCLUDE_THREAD_CALLBACK IncludeThread;
#     MINIDUMP_INCLUDE_MODULE_CALLBACK IncludeModule;
#     MINIDUMP_IO_CALLBACK Io;
#     MINIDUMP_READ_MEMORY_FAILURE_CALLBACK ReadMemoryFailure;
#     ULONG SecondaryFlags;
#   } ;
# } MINIDUMP_CALLBACK_INPUT, *PMINIDUMP_CALLBACK_INPUT;
class MINIDUMP_CALLBACK_INPUT_UNION (Union):
    _fields_ = [
        ("Status",              HRESULT),
        ("Thread",              MINIDUMP_THREAD_CALLBACK),
        ("ThreadEx",            MINIDUMP_THREAD_EX_CALLBACK),
        ("Module",              MINIDUMP_MODULE_CALLBACK),
        ("IncludeThread",       MINIDUMP_INCLUDE_THREAD_CALLBACK),
        ("IncludeModule",       MINIDUMP_INCLUDE_MODULE_CALLBACK),
        ("Io",                  MINIDUMP_IO_CALLBACK),
        ("ReadMemoryFailure",   MINIDUMP_READ_MEMORY_FAILURE_CALLBACK),
        ("SecondaryFlags",      ULONG),
    ]
class MINIDUMP_CALLBACK_INPUT_UNION (Union):
    _fields_ = [
        ("ProcessId",           ULONG),
        ("ProcessHandle",       HANDLE),
        ("CallbackType",        ULONG),
        ("u",                   MINIDUMP_CALLBACK_INPUT_UNION),
    ]

# typedef struct _MINIDUMP_CALLBACK_INPUT {
#   ULONG  ProcessId;
#   HANDLE ProcessHandle;
#   ULONG  CallbackType;
#   union {
#     HRESULT Status;
#     MINIDUMP_THREAD_CALLBACK Thread;
#     MINIDUMP_THREAD_EX_CALLBACK ThreadEx;
#     MINIDUMP_MODULE_CALLBACK Module;
#     MINIDUMP_INCLUDE_THREAD_CALLBACK IncludeThread;
#     MINIDUMP_INCLUDE_MODULE_CALLBACK IncludeModule;
#     MINIDUMP_IO_CALLBACK Io;
#     MINIDUMP_READ_MEMORY_FAILURE_CALLBACK ReadMemoryFailure;
#     ULONG SecondaryFlags;
#   } ;
# }MINIDUMP_CALLBACK_INPUT, *PMINIDUMP_CALLBACK_INPUT;
class _MINIDUMP_CALLBACK_INPUT_UNION (Union):
    _fields_ = [
        ("Status",              HRESULT),
        ("Thread",              MINIDUMP_THREAD_CALLBACK),
        ("ThreadEx",            MINIDUMP_THREAD_EX_CALLBACK),
        ("Module",              MINIDUMP_MODULE_CALLBACK),
        ("IncludeThread",       MINIDUMP_INCLUDE_THREAD_CALLBACK),
        ("IncludeModule",       MINIDUMP_INCLUDE_MODULE_CALLBACK),
        ("Io",                  MINIDUMP_IO_CALLBACK),
        ("ReadMemoryFailure",   MINIDUMP_READ_MEMORY_FAILURE_CALLBACK),
        ("SecondaryFlags",      ULONG),
    ]
class MINIDUMP_CALLBACK_INPUT (Structure):
    _fields_ = [
        ("ProcessId",       ULONG),
        ("ProcessHandle",   HANDLE),
        ("CallbackType",    ULONG),
        ("u",               _MINIDUMP_CALLBACK_INPUT_UNION),
    ]
PMINIDUMP_CALLBACK_INPUT = POINTER(MINIDUMP_CALLBACK_INPUT)

# BOOL CALLBACK MiniDumpCallback(
#   __in     PVOID CallbackParam,
#   __in     const PMINIDUMP_CALLBACK_INPUT CallbackInput,
#   __inout  PMINIDUMP_CALLBACK_OUTPUT CallbackOutput
# );
MINIDUMP_CALLBACK_ROUTINE = ctypes.WINFUNCTYPE(PVOID, PMINIDUMP_CALLBACK_INPUT, PMINIDUMP_CALLBACK_OUTPUT)

# typedef struct _MINIDUMP_CALLBACK_INFORMATION {
#   MINIDUMP_CALLBACK_ROUTINE CallbackRoutine;
#   PVOID                     CallbackParam;
# } MINIDUMP_CALLBACK_INFORMATION, *PMINIDUMP_CALLBACK_INFORMATION;
class MINIDUMP_CALLBACK_INFORMATION (Structure):
    _fields_ = [
        ("CallbackRoutine",     MINIDUMP_CALLBACK_ROUTINE),
        ("CallbackParam",       PVOID),
    ]

PMINIDUMP_CALLBACK_INFORMATION = POINTER(MINIDUMP_CALLBACK_INFORMATION)

#--- Functions ----------------------------------------------------------------

# XXX the ANSI versions of these functions don't end in "A" as expected!

# BOOL WINAPI SymInitialize(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR UserSearchPath,
#   __in      BOOL fInvadeProcess
# );
def SymInitializeA(hProcess, UserSearchPath = None, fInvadeProcess = False):
    if not UserSearchPath:
        UserSearchPath = NULL
    else:
        UserSearchPath = ctypes.create_string_buffer(UserSearchPath)
        UserSearchPath = ctypes.byref(UserSearchPath)
    if fInvadeProcess:
        fInvadeProcess = TRUE
    else:
        fInvadeProcess = FALSE
    success = ctypes.windll.dbghelp.SymInitialize(hProcess, UserSearchPath, fInvadeProcess)
    if success == FALSE:
        raise ctypes.WinError()
def SymInitializeW(hProcess, UserSearchPath = None, fInvadeProcess = False):
    if UserSearchPath:
        UserSearchPath = str(UserSearchPath)
    SymInitializeA(hProcess, UserSearchPath, fInvadeProcess)
SymInitialize = SymInitializeA

# BOOL WINAPI SymCleanup(
#   __in  HANDLE hProcess
# );
def SymCleanup(hProcess):
    success = ctypes.windll.dbghelp.SymCleanup(hProcess)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI SymRefreshModuleList(
#   __in  HANDLE hProcess
# );
def SymRefreshModuleList(hProcess):
    success = ctypes.windll.dbghelp.SymRefreshModuleList(hProcess)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI SymSetParentWindow(
#   __in  HWND hwnd
# );
def SymSetParentWindow(hwnd):
    success = ctypes.windll.dbghelp.SymSetParentWindow(hwnd)
    if success == FALSE:
        raise ctypes.WinError()

# DWORD WINAPI SymSetOptions(
#   __in  DWORD SymOptions
# );
def SymSetOptions(SymOptions):
    success = ctypes.windll.dbghelp.SymSetOptions(SymOptions)
    if success == FALSE:
        raise ctypes.WinError()

# DWORD WINAPI SymGetOptions(void);
def SymGetOptions():
    return ctypes.windll.dbghelp.SymGetOptions()

# DWORD64 WINAPI SymLoadModule(
#   __in      HANDLE hProcess,
#   __in_opt  HANDLE hFile,
#   __in_opt  PCSTR ImageName,
#   __in_opt  PCSTR ModuleName,
#   __in      DWORD BaseOfDll,
#   __in      DWORD SizeOfDll
# );
def SymLoadModule(hProcess, hFile = None, ImageName = None, ModuleName = None, BaseOfDll = None, SizeOfDll = None):
    if not hFile:
        hFile = NULL
    if not ImageName:
        ImageName = NULL
    else:
        ImageName = ctypes.create_string_buffer(ImageName)
        ImageName = ctypes.byref(ImageName)
    if not ModuleName:
        ModuleName = NULL
    else:
        ModuleName = ctypes.create_string_buffer(ModuleName)
        ModuleName = ctypes.byref(ModuleName)
    if not BaseOfDll:
        BaseOfDll = NULL
    if not SizeOfDll:
        SizeOfDll = NULL
    lpBaseAddress = ctypes.windll.dbghelp.SymLoadModule(hProcess, hFile, ImageName, ModuleName, BaseOfDll, SizeOfDll)
    if lpBaseAddress == NULL:
        dwErrorCode = GetLastError()
        if dwErrorCode != ERROR_SUCCESS:
            raise ctypes.WinError(dwErrorCode)
    return lpBaseAddress

# BOOL WINAPI SymUnloadModule(
#   __in  HANDLE hProcess,
#   __in  DWORD BaseOfDll
# );
def SymUnloadModule(hProcess, BaseOfDll):
    success = ctypes.windll.dbghelp.SymUnloadModule(hProcess, BaseOfDll)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI SymGetModuleInfo(
#   __in   HANDLE hProcess,
#   __in   DWORD dwAddr,
#   __out  PIMAGEHLP_MODULE ModuleInfo
# );
def SymGetModuleInfoA(hProcess, dwAddr):
    ModuleInfo = IMAGEHLP_MODULE()
    ModuleInfo.SizeOfStruct = ctypes.sizeof(ModuleInfo)
    success = ctypes.windll.dbghelp.SymGetModuleInfo(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    if success == FALSE:
        raise ctypes.WinError()
    return ModuleInfo
def SymGetModuleInfoW(hProcess, dwAddr):
    ModuleInfo = IMAGEHLP_MODULEW()
    ModuleInfo.SizeOfStruct = ctypes.sizeof(ModuleInfo)
    success = ctypes.windll.dbghelp.SymGetModuleInfoW(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    if success == FALSE:
        raise ctypes.WinError()
    return ModuleInfo

# BOOL CALLBACK SymEnumerateModulesProc64(
#   __in      PCTSTR ModuleName,
#   __in      DWORD64 BaseOfDll,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMMODULES_CALLBACK    = ctypes.WINFUNCTYPE(BOOL, ctypes.POINTER(CHAR),  DWORD,   PVOID)
PSYM_ENUMMODULES_CALLBACKW   = ctypes.WINFUNCTYPE(BOOL, ctypes.POINTER(WCHAR), DWORD,   PVOID)
PSYM_ENUMMODULES_CALLBACK64  = ctypes.WINFUNCTYPE(BOOL, ctypes.POINTER(CHAR),  DWORD64, PVOID)
PSYM_ENUMMODULES_CALLBACKW64 = ctypes.WINFUNCTYPE(BOOL, ctypes.POINTER(WCHAR), DWORD64, PVOID)

# BOOL WINAPI SymEnumerateModules64(
#   __in      HANDLE hProcess,
#   __in      PSYM_ENUMMODULES_CALLBACK64 EnumModulesCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateModulesA(hProcess, BaseOfDll, EnumModulesCallback, UserContext = None):
    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACK(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = NULL
    success = ctypes.windll.dbghelp.SymEnumerateModules(hProcess, BaseOfDll, EnumModulesCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
def SymEnumerateModulesW(hProcess, BaseOfDll, EnumModulesCallback, UserContext = None):
    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACKW(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = NULL
    success = ctypes.windll.dbghelp.SymEnumerateModulesW(hProcess, BaseOfDll, EnumModulesCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
SymEnumerateModules = SymEnumerateModulesA

# BOOL CALLBACK SymEnumerateSymbolsProc64(
#   __in      PCTSTR SymbolName,
#   __in      DWORD64 SymbolAddress,
#   __in      ULONG SymbolSize,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMSYMBOLS_CALLBACK    = ctypes.WINFUNCTYPE(BOOL, ctypes.c_char_p,  DWORD,   ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW   = ctypes.WINFUNCTYPE(BOOL, ctypes.c_wchar_p, DWORD,   ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACK64  = ctypes.WINFUNCTYPE(BOOL, ctypes.c_char_p,  DWORD64, ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW64 = ctypes.WINFUNCTYPE(BOOL, ctypes.c_wchar_p, DWORD64, ULONG, PVOID)

# BOOL WINAPI SymEnumerateSymbols(
#   __in      HANDLE hProcess,
#   __in      ULONG BaseOfDll,
#   __in      PSYM_ENUMSYMBOLS_CALLBACK EnumSymbolsCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateSymbolsA(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACK(EnumSymbolsCallback)
    EnumSymbolsCallback.restype = BOOL
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = NULL
    success = ctypes.windll.dbghelp.SymEnumerateSymbols(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
def SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACKW(EnumSymbolsCallback)
    EnumSymbolsCallback.restype = BOOL
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = NULL
    success = ctypes.windll.dbghelp.SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
SymEnumerateSymbols = SymEnumerateSymbolsA

# DWORD64 WINAPI SymLoadModule64(
#   __in      HANDLE hProcess,
#   __in_opt  HANDLE hFile,
#   __in_opt  PCSTR ImageName,
#   __in_opt  PCSTR ModuleName,
#   __in      DWORD64 BaseOfDll,
#   __in      DWORD SizeOfDll
# );

# XXX TO DO

# BOOL WINAPI SymUnloadModule64(
#   __in  HANDLE hProcess,
#   __in  DWORD64 BaseOfDll
# );

# XXX TO DO

# BOOL WINAPI SymGetModuleInfo64(
#   __in   HANDLE hProcess,
#   __in   DWORD64 dwAddr,
#   __out  PIMAGEHLP_MODULE64 ModuleInfo
# );

# XXX TO DO

# BOOL WINAPI SymEnumerateSymbols64(
#   __in      HANDLE hProcess,
#   __in      ULONG64 BaseOfDll,
#   __in      PSYM_ENUMSYMBOLS_CALLBACK64 EnumSymbolsCallback,
#   __in_opt  PVOID UserContext
# );

# XXX TO DO

# DWORD WINAPI UnDecorateSymbolName(
#   __in   PCTSTR DecoratedName,
#   __out  PTSTR UnDecoratedName,
#   __in   DWORD UndecoratedLength,
#   __in   DWORD Flags
# );

# XXX TO DO

# BOOL WINAPI SymGetSearchPath(
#   __in   HANDLE hProcess,
#   __out  PTSTR SearchPath,
#   __in   DWORD SearchPathLength
# );
def SymGetSearchPathA(hProcess):
    SearchPathLength = MAX_PATH
    SearchPath = ctypes.byref(ctypes.create_string_buffer("", SearchPathLength))
    success = ctypes.windll.dbghelp.SymGetSearchPath(hProcess, SearchPath, SearchPathLength)
    if success == FALSE:
        raise ctypes.WinError()
    return SearchPath.value
def SymGetSearchPathW(hProcess):
    SearchPathLength = MAX_PATH
    SearchPath = ctypes.byref(ctypes.create_unicode_buffer("", SearchPathLength))
    success = ctypes.windll.dbghelp.SymGetSearchPathW(hProcess, SearchPath, SearchPathLength)
    if success == FALSE:
        raise ctypes.WinError()
    return SearchPath.value
SymGetSearchPath = SymGetSearchPathA

# BOOL WINAPI SymSetSearchPath(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR SearchPath
# );
def SymSetSearchPathA(hProcess, SearchPath = None):
    if SearchPath:
        SearchPath = ctypes.byref(ctypes.create_string_buffer(SearchPath))
    else:
        SearchPath = NULL
    success = ctypes.windll.dbghelp.SymSetSearchPath(hProcess, SearchPath)
    if success == FALSE:
        raise ctypes.WinError()
def SymSetSearchPathW(hProcess, SearchPath = None):
    if SearchPath:
        SearchPath = ctypes.byref(ctypes.create_unicode_buffer(SearchPath))
    else:
        SearchPath = NULL
    success = ctypes.windll.dbghelp.SymSetSearchPathW(hProcess, SearchPath)
    if success == FALSE:
        raise ctypes.WinError()
SymSetSearchPath = SymSetSearchPathA

# BOOL WINAPI MiniDumpWriteDump(
#   __in  HANDLE hProcess,
#   __in  DWORD ProcessId,
#   __in  HANDLE hFile,
#   __in  MINIDUMP_TYPE DumpType,
#   __in  PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
#   __in  PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
#   __in  PMINIDUMP_CALLBACK_INFORMATION CallbackParam
# );
def MiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam):
    # XXX TODO
    # maybe this should be wrapped using Python types only?
    success = ctypes.windll.dbghelp.MiniDumpWriteDump(hProcess, ProcessId, hFile, DumpType, ctypes.byref(ExceptionParam), ctypes.byref(UserStreamParam), ctypes.byref(CallbackParam))
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI MiniDumpReadDumpStream(
#   __in   PVOID BaseOfDump,
#   __in   ULONG StreamNumber,
#   __out  PMINIDUMP_DIRECTORY *Dir,
#   __out  PVOID *StreamPointer,
#   __out  ULONG *StreamSize
# );
def MiniDumpReadDumpStream(BaseOfDump, StreamNumber):
    # XXX TODO
    # maybe this should be wrapped using Python types only?
    Dir             = MINIDUMP_DIRECTORY()
    StreamPointer   = PVOID(0)
    StreamSize      = ULONG(0)
    success = ctypes.windll.dbghelp.MiniDumpReadDumpStream(BaseOfDump, StreamNumber, ctypes.byref(Dir), ctypes.byref(StreamPointer), ctypes.byref(StreamSize))
    if success == FALSE:
        raise ctypes.WinError()
    return (Dir, StreamPointer, StreamSize.value)
