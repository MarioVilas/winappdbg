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

#--- Constants ----------------------------------------------------------------

# DEP flags for ProcessExecuteFlags
MEM_EXECUTE_OPTION_ENABLE               = 1
MEM_EXECUTE_OPTION_DISABLE              = 2
MEM_EXECUTE_OPTION_ATL7_THUNK_EMULATION = 4
MEM_EXECUTE_OPTION_PERMANENT            = 8

# NtQuerySystemInformation() constants from:
# http://www.informit.com/articles/article.aspx?p=22442&seqNum=4
SystemBasicInformation                  = 1     # 0x002C
SystemProcessorInformation              = 2     # 0x000C
SystemPerformanceInformation            = 3     # 0x0138
SystemTimeInformation                   = 4     # 0x0020
SystemPathInformation                   = 5     # not implemented
SystemProcessInformation                = 6     # 0x00F8 + per process
SystemCallInformation                   = 7     # 0x0018 + (n * 0x0004)
SystemConfigurationInformation          = 8     # 0x0018
SystemProcessorCounters                 = 9     # 0x0030 per cpu
SystemGlobalFlag                        = 10    # 0x0004
SystemInfo10                            = 11    # not implemented
SystemModuleInformation                 = 12    # 0x0004 + (n * 0x011C)
SystemLockInformation                   = 13    # 0x0004 + (n * 0x0024)
SystemInfo13                            = 14    # not implemented
SystemPagedPoolInformation              = 15    # checked build only
SystemNonPagedPoolInformation           = 16    # checked build only
SystemHandleInformation                 = 17    # 0x0004 + (n * 0x0010)
SystemObjectInformation                 = 18    # 0x0038+ + (n * 0x0030+)
SystemPagefileInformation               = 19    # 0x0018+ per page file
SystemInstemulInformation               = 20    # 0x0088
SystemInfo20                            = 21    # invalid info class
SystemCacheInformation                  = 22    # 0x0024
SystemPoolTagInformation                = 23    # 0x0004 + (n * 0x001C)
SystemProcessorStatistics               = 24    # 0x0000, or 0x0018 per cpu
SystemDpcInformation                    = 25    # 0x0014
SystemMemoryUsageInformation1           = 26    # checked build only
SystemLoadImage                         = 27    # 0x0018, set mode only
SystemUnloadImage                       = 28    # 0x0004, set mode only
SystemTimeAdjustmentInformation         = 29    # 0x000C, 0x0008 writeable
SystemMemoryUsageInformation2           = 30    # checked build only
SystemInfo30                            = 31    # checked build only
SystemInfo31                            = 32    # checked build only
SystemCrashDumpInformation              = 33    # 0x0004
SystemExceptionInformation              = 34    # 0x0010
SystemCrashDumpStateInformation         = 35    # 0x0008
SystemDebuggerInformation               = 36    # 0x0002
SystemThreadSwitchInformation           = 37    # 0x0030
SystemRegistryQuotaInformation          = 38    # 0x000C
SystemLoadDriver                        = 39    # 0x0008, set mode only
SystemPrioritySeparationInformation     = 40    # 0x0004, set mode only
SystemInfo40                            = 41    # not implemented
SystemInfo41                            = 42    # not implemented
SystemInfo42                            = 43    # invalid info class
SystemInfo43                            = 44    # invalid info class
SystemTimeZoneInformation               = 45    # 0x00AC
SystemLookasideInformation              = 46    # n * 0x0020
# info classes specific to Windows 2000
# WTS = Windows Terminal Server
SystemSetTimeSlipEvent                  = 47    # set mode only
SystemCreateSession                     = 48    # WTS, set mode only
SystemDeleteSession                     = 49    # WTS, set mode only
SystemInfo49                            = 50    # invalid info class
SystemRangeStartInformation             = 51    # 0x0004
SystemVerifierInformation               = 52    # 0x0068
SystemAddVerifier                       = 53    # set mode only
SystemSessionProcessesInformation       = 54    # WTS

# NtQueryInformationProcess constants (from MSDN)
##ProcessBasicInformation = 0
##ProcessDebugPort        = 7
##ProcessWow64Information = 26
##ProcessImageFileName    = 27

# NtQueryInformationProcess constants
# http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PROCESS_INFORMATION_CLASS.html
ProcessBasicInformation             = 0
ProcessQuotaLimits                  = 1
ProcessIoCounters                   = 2
ProcessVmCounters                   = 3
ProcessTimes                        = 4
ProcessBasePriority                 = 5
ProcessRaisePriority                = 6
ProcessDebugPort                    = 7
ProcessExceptionPort                = 8
ProcessAccessToken                  = 9
ProcessLdtInformation               = 10
ProcessLdtSize                      = 11
ProcessDefaultHardErrorMode         = 12
ProcessIoPortHandlers               = 13
ProcessPooledUsageAndLimits         = 14
ProcessWorkingSetWatch              = 15
ProcessUserModeIOPL                 = 16
ProcessEnableAlignmentFaultFixup    = 17
ProcessPriorityClass                = 18
ProcessWx86Information              = 19
ProcessHandleCount                  = 20
ProcessAffinityMask                 = 21
ProcessPriorityBoost                = 22

ProcessWow64Information             = 26
ProcessImageFileName                = 27

ProcessExecuteFlags                 = 34

# NtQueryInformationThread constants
#
ThreadBasicInformation          = 0
ThreadTimes                     = 1
ThreadPriority                  = 2
ThreadBasePriority              = 3
ThreadAffinityMask              = 4
ThreadImpersonationToken        = 5
ThreadDescriptorTableEntry      = 6
ThreadEnableAlignmentFaultFixup = 7
ThreadEventPair                 = 8
ThreadQuerySetWin32StartAddress = 9
ThreadZeroTlsCell               = 10
ThreadPerformanceCount          = 11
ThreadAmILastThread             = 12
ThreadIdealProcessor            = 13
ThreadPriorityBoost             = 14
ThreadSetTlsArrayAddress        = 15
ThreadIsIoPending               = 16
ThreadHideFromDebugger          = 17

# From http://www.nirsoft.net/kernel_struct/vista/EXCEPTION_DISPOSITION.html
# typedef enum _EXCEPTION_DISPOSITION
# {
#          ExceptionContinueExecution = 0,
#          ExceptionContinueSearch = 1,
#          ExceptionNestedException = 2,
#          ExceptionCollidedUnwind = 3
# } EXCEPTION_DISPOSITION;
ExceptionContinueExecution  = 0
ExceptionContinueSearch     = 1
ExceptionNestedException    = 2
ExceptionCollidedUnwind     = 3

#--- PEB and TEB structure, constants and data types --------------------------

# From http://www.nirsoft.net/kernel_struct/vista/CLIENT_ID.html
#
# typedef struct _CLIENT_ID
# {
#     PVOID UniqueProcess;
#     PVOID UniqueThread;
# } CLIENT_ID, *PCLIENT_ID;
class CLIENT_ID(Structure):
    _fields_ = [
        ("UniqueProcess",   PVOID),
        ("UniqueThread",    PVOID),
]

# From MSDN:
#
# typedef struct _LDR_DATA_TABLE_ENTRY {
#     BYTE Reserved1[2];
#     LIST_ENTRY InMemoryOrderLinks;
#     PVOID Reserved2[2];
#     PVOID DllBase;
#     PVOID EntryPoint;
#     PVOID Reserved3;
#     UNICODE_STRING FullDllName;
#     BYTE Reserved4[8];
#     PVOID Reserved5[3];
#     union {
#         ULONG CheckSum;
#         PVOID Reserved6;
#     };
#     ULONG TimeDateStamp;
# } LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
##class LDR_DATA_TABLE_ENTRY(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",           BYTE * 2),
##        ("InMemoryOrderLinks",  LIST_ENTRY),
##        ("Reserved2",           PVOID * 2),
##        ("DllBase",             PVOID),
##        ("EntryPoint",          PVOID),
##        ("Reserved3",           PVOID),
##        ("FullDllName",           UNICODE_STRING),
##        ("Reserved4",           BYTE * 8),
##        ("Reserved5",           PVOID * 3),
##        ("CheckSum",            ULONG),
##        ("TimeDateStamp",       ULONG),
##]

# From MSDN:
#
# typedef struct _PEB_LDR_DATA {
#   BYTE         Reserved1[8];
#   PVOID        Reserved2[3];
#   LIST_ENTRY   InMemoryOrderModuleList;
# } PEB_LDR_DATA,
#  *PPEB_LDR_DATA;
##class PEB_LDR_DATA(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",               BYTE),
##        ("Reserved2",               PVOID),
##        ("InMemoryOrderModuleList", LIST_ENTRY),
##]

# From MSDN:
#
# typedef struct _RTL_USER_PROCESS_PARAMETERS {
#   BYTE             Reserved1[16];
#   PVOID            Reserved2[10];
#   UNICODE_STRING   ImagePathName;
#   UNICODE_STRING   CommandLine;
# } RTL_USER_PROCESS_PARAMETERS,
#  *PRTL_USER_PROCESS_PARAMETERS;
##class RTL_USER_PROCESS_PARAMETERS(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",               BYTE * 16),
##        ("Reserved2",               PVOID * 10),
##        ("ImagePathName",           UNICODE_STRING),
##        ("CommandLine",             UNICODE_STRING),
##]

##PPS_POST_PROCESS_INIT_ROUTINE = PVOID

#from MSDN:
#
# typedef struct _PEB {
#     BYTE Reserved1[2];
#     BYTE BeingDebugged;
#     BYTE Reserved2[21];
#     PPEB_LDR_DATA LoaderData;
#     PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
#     BYTE Reserved3[520];
#     PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
#     BYTE Reserved4[136];
#     ULONG SessionId;
# } PEB;
##class PEB(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",               BYTE * 2),
##        ("BeingDebugged",           BYTE),
##        ("Reserved2",               BYTE * 21),
##        ("LoaderData",              POINTER(PEB_LDR_DATA)),
##        ("ProcessParameters",       POINTER(RTL_USER_PROCESS_PARAMETERS)),
##        ("Reserved3",               BYTE * 520),
##        ("PostProcessInitRoutine",  PPS_POST_PROCESS_INIT_ROUTINE),
##        ("Reserved4",               BYTE),
##        ("SessionId",               ULONG),
##]

# from MSDN:
#
# typedef struct _TEB {
#   BYTE    Reserved1[1952];
#   PVOID   Reserved2[412];
#   PVOID   TlsSlots[64];
#   BYTE    Reserved3[8];
#   PVOID   Reserved4[26];
#   PVOID   ReservedForOle;
#   PVOID   Reserved5[4];
#   PVOID   TlsExpansionSlots;
# } TEB,
#  *PTEB;
##class TEB(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("Reserved1",           PVOID * 1952),
##        ("Reserved2",           PVOID * 412),
##        ("TlsSlots",            PVOID * 64),
##        ("Reserved3",           BYTE  * 8),
##        ("Reserved4",           PVOID * 26),
##        ("ReservedForOle",      PVOID),
##        ("Reserved5",           PVOID * 4),
##        ("TlsExpansionSlots",   PVOID),
##]

# from http://undocumented.ntinternals.net/UserMode/Structures/LDR_MODULE.html
#
# typedef struct _LDR_MODULE {
#   LIST_ENTRY InLoadOrderModuleList;
#   LIST_ENTRY InMemoryOrderModuleList;
#   LIST_ENTRY InInitializationOrderModuleList;
#   PVOID BaseAddress;
#   PVOID EntryPoint;
#   ULONG SizeOfImage;
#   UNICODE_STRING FullDllName;
#   UNICODE_STRING BaseDllName;
#   ULONG Flags;
#   SHORT LoadCount;
#   SHORT TlsIndex;
#   LIST_ENTRY HashTableEntry;
#   ULONG TimeDateStamp;
# } LDR_MODULE, *PLDR_MODULE;
class LDR_MODULE(Structure):
    _pack_ = 1
    _fields_ = [
        ("InLoadOrderModuleList",           LIST_ENTRY),
        ("InMemoryOrderModuleList",         LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
        ("BaseAddress",                     PVOID),
        ("EntryPoint",                      PVOID),
        ("SizeOfImage",                     ULONG),
        ("FullDllName",                     UNICODE_STRING),
        ("BaseDllName",                     UNICODE_STRING),
        ("Flags",                           ULONG),
        ("LoadCount",                       SHORT),
        ("TlsIndex",                        SHORT),
        ("HashTableEntry",                  LIST_ENTRY),
        ("TimeDateStamp",                   ULONG),
]

# from http://undocumented.ntinternals.net/UserMode/Structures/PEB_LDR_DATA.html
#
# typedef struct _PEB_LDR_DATA {
#   ULONG Length;
#   BOOLEAN Initialized;
#   PVOID SsHandle;
#   LIST_ENTRY InLoadOrderModuleList;
#   LIST_ENTRY InMemoryOrderModuleList;
#   LIST_ENTRY InInitializationOrderModuleList;
# } PEB_LDR_DATA, *PPEB_LDR_DATA;
class PEB_LDR_DATA(Structure):
    _pack_ = 1
    _fields_ = [
        ("Length",                          ULONG),
        ("Initialized",                     BOOLEAN),
        ("SsHandle",                        PVOID),
        ("InLoadOrderModuleList",           LIST_ENTRY),
        ("InMemoryOrderModuleList",         LIST_ENTRY),
        ("InInitializationOrderModuleList", LIST_ENTRY),
]

# From http://undocumented.ntinternals.net/UserMode/Undocumented%20Functions/NT%20Objects/Process/PEB_FREE_BLOCK.html
#
# typedef struct _PEB_FREE_BLOCK {
#   PEB_FREE_BLOCK *Next;
#   ULONG Size;
# } PEB_FREE_BLOCK, *PPEB_FREE_BLOCK;
class PEB_FREE_BLOCK(Structure):
    pass

##PPEB_FREE_BLOCK = POINTER(PEB_FREE_BLOCK)
PPEB_FREE_BLOCK = PVOID

PEB_FREE_BLOCK._fields_ = [
        ("Next", PPEB_FREE_BLOCK),
        ("Size", ULONG),
]

# From http://undocumented.ntinternals.net/UserMode/Structures/RTL_DRIVE_LETTER_CURDIR.html
#
# typedef struct _RTL_DRIVE_LETTER_CURDIR {
#   USHORT Flags;
#   USHORT Length;
#   ULONG TimeStamp;
#   UNICODE_STRING DosPath;
# } RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;
class RTL_DRIVE_LETTER_CURDIR(Structure):
    _fields_ = [
        ("Flags",       USHORT),
        ("Length",      USHORT),
        ("TimeStamp",   ULONG),
        ("DosPath",     UNICODE_STRING),
]

# From http://www.nirsoft.net/kernel_struct/vista/CURDIR.html
#
# typedef struct _CURDIR
# {
#      UNICODE_STRING DosPath;
#      PVOID Handle;
# } CURDIR, *PCURDIR;
class CURDIR(Structure):
    _fields_ = [
        ("DosPath", UNICODE_STRING),
        ("Handle",  PVOID),
]

# From MSDN:
#
# typedef struct _RTL_USER_PROCESS_PARAMETERS {
#   BYTE           Reserved1[16];
#   PVOID          Reserved2[10];
#   UNICODE_STRING ImagePathName;
#   UNICODE_STRING CommandLine;
# } RTL_USER_PROCESS_PARAMETERS,
# *PRTL_USER_PROCESS_PARAMETERS;
class RTL_USER_PROCESS_PARAMETERS(Structure):
    _fields_ = [
        ("Reserved1",       BYTE * 16),
        ("Reserved2",       PVOID * 10),
        ("ImagePathName",   UNICODE_STRING),
        ("CommandLine",     UNICODE_STRING),
]

# kd> dt _RTL_USER_PROCESS_PARAMETERS
# ntdll!_RTL_USER_PROCESS_PARAMETERS
#    +0x000 MaximumLength    : Uint4B
#    +0x004 Length           : Uint4B
#    +0x008 Flags            : Uint4B
#    +0x00c DebugFlags       : Uint4B
#    +0x010 ConsoleHandle    : Ptr32 Void
#    +0x014 ConsoleFlags     : Uint4B
#    +0x018 StandardInput    : Ptr32 Void
#    +0x01c StandardOutput   : Ptr32 Void
#    +0x020 StandardError    : Ptr32 Void
#    +0x024 CurrentDirectory : _CURDIR
#    +0x030 DllPath          : _UNICODE_STRING
#    +0x038 ImagePathName    : _UNICODE_STRING
#    +0x040 CommandLine      : _UNICODE_STRING
#    +0x048 Environment      : Ptr32 Void
#    +0x04c StartingX        : Uint4B
#    +0x050 StartingY        : Uint4B
#    +0x054 CountX           : Uint4B
#    +0x058 CountY           : Uint4B
#    +0x05c CountCharsX      : Uint4B
#    +0x060 CountCharsY      : Uint4B
#    +0x064 FillAttribute    : Uint4B
#    +0x068 WindowFlags      : Uint4B
#    +0x06c ShowWindowFlags  : Uint4B
#    +0x070 WindowTitle      : _UNICODE_STRING
#    +0x078 DesktopInfo      : _UNICODE_STRING
#    +0x080 ShellInfo        : _UNICODE_STRING
#    +0x088 RuntimeData      : _UNICODE_STRING
#    +0x090 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
#    +0x290 EnvironmentSize  : Uint4B
##class RTL_USER_PROCESS_PARAMETERS(Structure):
##    _pack_ = 1
##    _fields_ = [
##        ("MaximumLength",           ULONG),
##        ("Length",                  ULONG),
##        ("Flags",                   ULONG),
##        ("DebugFlags",              ULONG),
##        ("ConsoleHandle",           PVOID),
##        ("ConsoleFlags",            ULONG),
##        ("StandardInput",           HANDLE),
##        ("StandardOutput",          HANDLE),
##        ("StandardError",           HANDLE),
##        ("CurrentDirectory",        CURDIR),
##        ("DllPath",                 UNICODE_STRING),
##        ("ImagePathName",           UNICODE_STRING),
##        ("CommandLine",             UNICODE_STRING),
##        ("Environment",             PVOID),
##        ("StartingX",               ULONG),
##        ("StartingY",               ULONG),
##        ("CountX",                  ULONG),
##        ("CountY",                  ULONG),
##        ("CountCharsX",             ULONG),
##        ("CountCharsY",             ULONG),
##        ("FillAttribute",           ULONG),
##        ("WindowFlags",             ULONG),
##        ("ShowWindowFlags",         ULONG),
##        ("WindowTitle",             UNICODE_STRING),
##        ("DesktopInfo",             UNICODE_STRING),
##        ("ShellInfo",               UNICODE_STRING),
##        ("RuntimeData",             UNICODE_STRING),
##        ("CurrentDirectores",       RTL_DRIVE_LETTER_CURDIR * 32), # typo here?
##
##        # Windows 2008 and Vista
##        ("EnvironmentSize",         ULONG),
##]
##    @property
##    def CurrentDirectories(self):
##        return self.CurrentDirectores

# From http://www.nirsoft.net/kernel_struct/vista/RTL_CRITICAL_SECTION_DEBUG.html
#
# typedef struct _RTL_CRITICAL_SECTION_DEBUG
# {
#      WORD Type;
#      WORD CreatorBackTraceIndex;
#      PRTL_CRITICAL_SECTION CriticalSection;
#      LIST_ENTRY ProcessLocksList;
#      ULONG EntryCount;
#      ULONG ContentionCount;
#      ULONG Flags;
#      WORD CreatorBackTraceIndexHigh;
#      WORD SpareUSHORT;
# } RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG;
#
# From http://www.nirsoft.net/kernel_struct/vista/RTL_CRITICAL_SECTION.html
#
# typedef struct _RTL_CRITICAL_SECTION
# {
#      PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
#      LONG LockCount;
#      LONG RecursionCount;
#      PVOID OwningThread;
#      PVOID LockSemaphore;
#      ULONG SpinCount;
# } RTL_CRITICAL_SECTION, *PRTL_CRITICAL_SECTION;
#
class RTL_CRITICAL_SECTION(Structure):
    _pack_ = 1
class RTL_CRITICAL_SECTION_DEBUG(Structure):
    _pack_ = 1
##PRTL_CRITICAL_SECTION       = POINTER(RTL_CRITICAL_SECTION)
##PRTL_CRITICAL_SECTION_DEBUG = POINTER(RTL_CRITICAL_SECTION_DEBUG)
PRTL_CRITICAL_SECTION       = PVOID
PRTL_CRITICAL_SECTION_DEBUG = PVOID
RTL_CRITICAL_SECTION._fields_ = [
        ("DebugInfo",       PRTL_CRITICAL_SECTION_DEBUG),
        ("LockCount",       LONG),
        ("RecursionCount",  LONG),
        ("OwningThread",    PVOID),
        ("LockSemaphore",   PVOID),
        ("SpinCount",       ULONG),
]
RTL_CRITICAL_SECTION_DEBUG._fields_ = [
        ("Type",                        WORD),
        ("CreatorBackTraceIndex",       WORD),
        ("CriticalSection",             PRTL_CRITICAL_SECTION),
        ("ProcessLocksList",            LIST_ENTRY),
        ("EntryCount",                  ULONG),
        ("ContentionCount",             ULONG),
        ("Flags",                       ULONG),
        ("CreatorBackTraceIndexHigh",   WORD),
        ("SpareUSHORT",                 WORD),
]

# kd> dt nt!_PEB
#    +0x000 InheritedAddressSpace : UChar
#    +0x001 ReadImageFileExecOptions : UChar
#    +0x002 BeingDebugged    : UChar
#    +0x003 BitField         : UChar
#    +0x003 ImageUsesLargePages : Pos 0, 1 Bit
#    +0x003 IsProtectedProcess : Pos 1, 1 Bit
#    +0x003 IsLegacyProcess  : Pos 2, 1 Bit
#    +0x003 IsImageDynamicallyRelocated : Pos 3, 1 Bit
#    +0x003 SpareBits        : Pos 4, 4 Bits
#    +0x004 Mutant           : Ptr32 Void
#    +0x008 ImageBaseAddress : Ptr32 Void
#    +0x00c Ldr              : Ptr32 _PEB_LDR_DATA
#    +0x010 ProcessParameters : Ptr32 _RTL_USER_PROCESS_PARAMETERS
#    +0x014 SubSystemData    : Ptr32 Void
#    +0x018 ProcessHeap      : Ptr32 Void
#    +0x01c FastPebLock      : Ptr32 _RTL_CRITICAL_SECTION
#    +0x020 AtlThunkSListPtr : Ptr32 Void
#    +0x024 IFEOKey          : Ptr32 Void
#    +0x028 CrossProcessFlags : Uint4B
#    +0x028 ProcessInJob     : Pos 0, 1 Bit
#    +0x028 ProcessInitializing : Pos 1, 1 Bit
#    +0x028 ReservedBits0    : Pos 2, 30 Bits
#    +0x02c KernelCallbackTable : Ptr32 Void
#    +0x02c UserSharedInfoPtr : Ptr32 Void
#    +0x030 SystemReserved   : [1] Uint4B
#    +0x034 SpareUlong       : Uint4B
#    +0x038 FreeList         : Ptr32 _PEB_FREE_BLOCK
#    +0x03c TlsExpansionCounter : Uint4B
#    +0x040 TlsBitmap        : Ptr32 Void
#    +0x044 TlsBitmapBits    : [2] Uint4B
#    +0x04c ReadOnlySharedMemoryBase : Ptr32 Void
#    +0x050 HotpatchInformation : Ptr32 Void
#    +0x054 ReadOnlyStaticServerData : Ptr32 Ptr32 Void
#    +0x058 AnsiCodePageData : Ptr32 Void
#    +0x05c OemCodePageData  : Ptr32 Void
#    +0x060 UnicodeCaseTableData : Ptr32 Void
#    +0x064 NumberOfProcessors : Uint4B
#    +0x068 NtGlobalFlag     : Uint4B
#    +0x070 CriticalSectionTimeout : _LARGE_INTEGER
#    +0x078 HeapSegmentReserve : Uint4B
#    +0x07c HeapSegmentCommit : Uint4B
#    +0x080 HeapDeCommitTotalFreeThreshold : Uint4B
#    +0x084 HeapDeCommitFreeBlockThreshold : Uint4B
#    +0x088 NumberOfHeaps    : Uint4B
#    +0x08c MaximumNumberOfHeaps : Uint4B
#    +0x090 ProcessHeaps     : Ptr32 Ptr32 Void
#    +0x094 GdiSharedHandleTable : Ptr32 Void
#    +0x098 ProcessStarterHelper : Ptr32 Void
#    +0x09c GdiDCAttributeList : Uint4B
#    +0x0a0 LoaderLock       : Ptr32 _RTL_CRITICAL_SECTION
#    +0x0a4 OSMajorVersion   : Uint4B
#    +0x0a8 OSMinorVersion   : Uint4B
#    +0x0ac OSBuildNumber    : Uint2B
#    +0x0ae OSCSDVersion     : Uint2B
#    +0x0b0 OSPlatformId     : Uint4B
#    +0x0b4 ImageSubsystem   : Uint4B
#    +0x0b8 ImageSubsystemMajorVersion : Uint4B
#    +0x0bc ImageSubsystemMinorVersion : Uint4B
#    +0x0c0 ImageProcessAffinityMask : Uint4B
#    +0x0c4 GdiHandleBuffer  : [34] Uint4B
#    +0x14c PostProcessInitRoutine : Ptr32     void
#    +0x150 TlsExpansionBitmap : Ptr32 Void
#    +0x154 TlsExpansionBitmapBits : [32] Uint4B
#    +0x1d4 SessionId        : Uint4B
#    +0x1d8 AppCompatFlags   : _ULARGE_INTEGER
#    +0x1e0 AppCompatFlagsUser : _ULARGE_INTEGER
#    +0x1e8 pShimData        : Ptr32 Void
#    +0x1ec AppCompatInfo    : Ptr32 Void
#    +0x1f0 CSDVersion       : _UNICODE_STRING
#    +0x1f8 ActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
#    +0x1fc ProcessAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
#    +0x200 SystemDefaultActivationContextData : Ptr32 _ACTIVATION_CONTEXT_DATA
#    +0x204 SystemAssemblyStorageMap : Ptr32 _ASSEMBLY_STORAGE_MAP
#    +0x208 MinimumStackCommit : Uint4B
#    +0x20c FlsCallback      : Ptr32 _FLS_CALLBACK_INFO
#    +0x210 FlsListHead      : _LIST_ENTRY
#    +0x218 FlsBitmap        : Ptr32 Void
#    +0x21c FlsBitmapBits    : [4] Uint4B
#    +0x22c FlsHighIndex     : Uint4B
#    +0x230 WerRegistrationData : Ptr32 Void
#    +0x234 WerShipAssertPtr : Ptr32 Void

##PPEB_LDR_DATA                   = POINTER(PEB_LDR_DATA)
##PRTL_USER_PROCESS_PARAMETERS    = POINTER(RTL_USER_PROCESS_PARAMETERS)
PPEB_LDR_DATA                   = PVOID
PRTL_USER_PROCESS_PARAMETERS    = PVOID

PPEBLOCKROUTINE                 = PVOID

# BitField
ImageUsesLargePages         = 1 << 0
IsProtectedProcess          = 1 << 1
IsLegacyProcess             = 1 << 2
IsImageDynamicallyRelocated = 1 << 3

# TODO
# Break down the PEB into multiple structures, once for each Windows version.
# Then autodetect the current Windows version and set the PEB symbol to the
# correct structure (while keeping the others for reference).
class PEB(Structure):
    _pack_ = 1
    _fields_ = [

        # Windows NT

        ("InheritedAddressSpace",               UCHAR),
        ("ReadImageFileExecOptions",            UCHAR),
        ("BeingDebugged",                       UCHAR),
        ("BitField",                            UCHAR),
        ("Mutant",                              HANDLE),
        ("ImageBaseAddress",                    PVOID),
        ("Ldr",                                 PPEB_LDR_DATA),
        ("ProcessParameters",                   PRTL_USER_PROCESS_PARAMETERS),
        ("SubSystemData",                       PVOID),
        ("ProcessHeap",                         PVOID),
        ("FastPebLock",                         PVOID),
        ("FastPebLockRoutine",                  PPEBLOCKROUTINE),
        ("FastPebUnlockRoutine",                PPEBLOCKROUTINE),
        ("EnvironmentUpdateCount",              ULONG),
        ("KernelCallbackTable",                 PPVOID),
        ("EventLogSection",                     PVOID),
        ("EventLog",                            PVOID),
        ("FreeList",                            PPEB_FREE_BLOCK),
        ("TlsExpansionCounter",                 ULONG),
        ("TlsBitmap",                           PVOID),
        ("TlsBitmapBits",                       ULONG * 2),
        ("ReadOnlySharedMemoryBase",            PVOID),
        ("ReadOnlySharedMemoryHeap",            PVOID),
        ("ReadOnlyStaticServerData",            PPVOID),
        ("AnsiCodePageData",                    PVOID),
        ("OemCodePageData",                     PVOID),
        ("UnicodeCaseTableData",                PVOID),
        ("NumberOfProcessors",                  ULONG),
        ("NtGlobalFlag",                        ULONG),
        ("Spare2",                              BYTE * 4),
        ("CriticalSectionTimeout",              LONGLONG),  # LARGE_INTEGER
        ("HeapSegmentReserve",                  ULONG),
        ("HeapSegmentCommit",                   ULONG),
        ("HeapDeCommitTotalFreeThreshold",      ULONG),
        ("HeapDeCommitFreeBlockThreshold",      ULONG),
        ("NumberOfHeaps",                       ULONG),
        ("MaximumNumberOfHeaps",                ULONG),
        ("ProcessHeaps",                        PPVOID),
        ("GdiSharedHandleTable",                PVOID),
        ("ProcessStarterHelper",                PVOID),
        ("GdiDCAttributeList",                  PVOID),
        ("LoaderLock",                          PRTL_CRITICAL_SECTION),
        ("OSMajorVersion",                      ULONG),
        ("OSMinorVersion",                      ULONG),
        ("OSBuildNumber",                       ULONG),
        ("OSPlatformId",                        ULONG),
        ("ImageSubSystem",                      ULONG),
        ("ImageSubSystemMajorVersion",          ULONG),
        ("ImageSubSystemMinorVersion",          ULONG),
        ("ImageProcessAffinityMask",            ULONG),
        ("GdiHandleBuffer",                     ULONG * 34),
        ("PostProcessInitRoutine",              ULONG),
        ("TlsExpansionBitmap",                  ULONG),
        ("TlsExpansionBitmapBits",              BYTE * 128),
        ("SessionId",                           ULONG),

        # Windows XP

        ("AppCompatFlags",                      ULONGLONG), # ULARGE_INTEGER
        ("AppCompatFlagsUser",                  ULONGLONG), # ULARGE_INTEGER
        ("pShimData",                           PVOID),
        ("AppCompatInfo",                       PVOID),
        ("CSDVersion",                          UNICODE_STRING),
        ("ActivationContextData",               PVOID), # PACTIVATION_CONTEXT_DATA
        ("ProcessAssemblyStorageMap",           PVOID), # PASSEMBLY_STORAGE_MAP
        ("SystemDefaultActivationContextData",  PVOID), # PACTIVATION_CONTEXT_DATA
        ("SystemAssemblyStorageMap",            PVOID), # PASSEMBLY_STORAGE_MAP
        ("MinimumStackCommit",                  ULONG),

        # Windows 2003

        ("FlsCallback",                         PVOID), # PFLS_CALLBACK_INFO
        ("FlsListHead",                         LIST_ENTRY),
        ("FlsBitmap",                           PVOID),
        ("FlsBitmapBits",                       ULONG * 4),
        ("FlsHighIndex",                        ULONG),

        # Windows 2008 and Vista

        ("WerRegistrationData",                 PVOID),
        ("WerShipAssertPtr",                    PVOID),
]

# from http://www.nirsoft.net/kernel_struct/vista/NT_TIB.html
#
# typedef struct _NT_TIB
# {
#      PEXCEPTION_REGISTRATION_RECORD ExceptionList;
#      PVOID StackBase;
#      PVOID StackLimit;
#      PVOID SubSystemTib;
#      union
#      {
#           PVOID FiberData;
#           ULONG Version;
#      };
#      PVOID ArbitraryUserPointer;
#      PNT_TIB Self;
# } NT_TIB, *PNT_TIB;
class _NT_TIB_UNION(Union):
    _fields_ = [
        ("FiberData",   PVOID),
        ("Version",     ULONG),
]
class NT_TIB(Structure):
    _fields_ = [
        ("StackBase",               PVOID),
        ("StackLimit",              PVOID),
        ("SubSystemTib",            PVOID),
        ("u",                       _NT_TIB_UNION),
        ("ArbitraryUserPointer",    PVOID),
        ("Self",                    PVOID),     # PNTTIB
]
PNTTIB = POINTER(NT_TIB)

# From http://www.nirsoft.net/kernel_struct/vista/EXCEPTION_REGISTRATION_RECORD.html
#
# typedef struct _EXCEPTION_REGISTRATION_RECORD
# {
#      PEXCEPTION_REGISTRATION_RECORD Next;
#      PEXCEPTION_DISPOSITION Handler;
# } EXCEPTION_REGISTRATION_RECORD, *PEXCEPTION_REGISTRATION_RECORD;
class EXCEPTION_REGISTRATION_RECORD(Structure):
    pass

EXCEPTION_DISPOSITION           = DWORD
##PEXCEPTION_DISPOSITION          = POINTER(EXCEPTION_DISPOSITION)
##PEXCEPTION_REGISTRATION_RECORD  = POINTER(EXCEPTION_REGISTRATION_RECORD)
PEXCEPTION_DISPOSITION          = PVOID
PEXCEPTION_REGISTRATION_RECORD  = PVOID

EXCEPTION_REGISTRATION_RECORD._fields_ = [
        ("Next",    PEXCEPTION_REGISTRATION_RECORD),
        ("Handler", PEXCEPTION_DISPOSITION),
]

##PPEB = POINTER(PEB)
PPEB = PVOID

# From http://www.nirsoft.net/kernel_struct/vista/GDI_TEB_BATCH.html
#
# typedef struct _GDI_TEB_BATCH
# {
#      ULONG Offset;
#      ULONG HDC;
#      ULONG Buffer[310];
# } GDI_TEB_BATCH, *PGDI_TEB_BATCH;
class GDI_TEB_BATCH(Structure):
    _fields_ = [
        ("Offset",  ULONG),
        ("HDC",     ULONG),
        ("Buffer",  ULONG * 310),
]

# kd> dt _TEB
#    +0x000 NtTib            : _NT_TIB
#    +0x01c EnvironmentPointer : Ptr32 Void
#    +0x020 ClientId         : _CLIENT_ID
#    +0x028 ActiveRpcHandle  : Ptr32 Void
#    +0x02c ThreadLocalStoragePointer : Ptr32 Void
#    +0x030 ProcessEnvironmentBlock : Ptr32 _PEB
#    +0x034 LastErrorValue   : Uint4B
#    +0x038 CountOfOwnedCriticalSections : Uint4B
#    +0x03c CsrClientThread  : Ptr32 Void
#    +0x040 Win32ThreadInfo  : Ptr32 Void
#    +0x044 User32Reserved   : [26] Uint4B
#    +0x0ac UserReserved     : [5] Uint4B
#    +0x0c0 WOW32Reserved    : Ptr32 Void
#    +0x0c4 CurrentLocale    : Uint4B
#    +0x0c8 FpSoftwareStatusRegister : Uint4B
#    +0x0cc SystemReserved1  : [54] Ptr32 Void
#    +0x1a4 ExceptionCode    : Int4B
#    +0x1a8 ActivationContextStackPointer : Ptr32 _ACTIVATION_CONTEXT_STACK
#    +0x1ac SpareBytes1      : [36] UChar
#    +0x1d0 TxFsContext      : Uint4B
#    +0x1d4 GdiTebBatch      : _GDI_TEB_BATCH
#    +0x6b4 RealClientId     : _CLIENT_ID
#    +0x6bc GdiCachedProcessHandle : Ptr32 Void
#    +0x6c0 GdiClientPID     : Uint4B
#    +0x6c4 GdiClientTID     : Uint4B
#    +0x6c8 GdiThreadLocalInfo : Ptr32 Void
#    +0x6cc Win32ClientInfo  : [62] Uint4B
#    +0x7c4 glDispatchTable  : [233] Ptr32 Void
#    +0xb68 glReserved1      : [29] Uint4B
#    +0xbdc glReserved2      : Ptr32 Void
#    +0xbe0 glSectionInfo    : Ptr32 Void
#    +0xbe4 glSection        : Ptr32 Void
#    +0xbe8 glTable          : Ptr32 Void
#    +0xbec glCurrentRC      : Ptr32 Void
#    +0xbf0 glContext        : Ptr32 Void
#    +0xbf4 LastStatusValue  : Uint4B
#    +0xbf8 StaticUnicodeString : _UNICODE_STRING
#    +0xc00 StaticUnicodeBuffer : [261] Wchar
#    +0xe0c DeallocationStack : Ptr32 Void
#    +0xe10 TlsSlots         : [64] Ptr32 Void
#    +0xf10 TlsLinks         : _LIST_ENTRY
#    +0xf18 Vdm              : Ptr32 Void
#    +0xf1c ReservedForNtRpc : Ptr32 Void
#    +0xf20 DbgSsReserved    : [2] Ptr32 Void
#    +0xf28 HardErrorMode    : Uint4B
#    +0xf2c Instrumentation  : [9] Ptr32 Void
#    +0xf50 ActivityId       : _GUID
#    +0xf60 SubProcessTag    : Ptr32 Void
#    +0xf64 EtwLocalData     : Ptr32 Void
#    +0xf68 EtwTraceData     : Ptr32 Void
#    +0xf6c WinSockData      : Ptr32 Void
#    +0xf70 GdiBatchCount    : Uint4B
#    +0xf74 SpareBool0       : UChar
#    +0xf75 SpareBool1       : UChar
#    +0xf76 SpareBool2       : UChar
#    +0xf77 IdealProcessor   : UChar
#    +0xf78 GuaranteedStackBytes : Uint4B
#    +0xf7c ReservedForPerf  : Ptr32 Void
#    +0xf80 ReservedForOle   : Ptr32 Void
#    +0xf84 WaitingOnLoaderLock : Uint4B
#    +0xf88 SavedPriorityState : Ptr32 Void
#    +0xf8c SoftPatchPtr1    : Uint4B
#    +0xf90 ThreadPoolData   : Ptr32 Void
#    +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
#    +0xf98 ImpersonationLocale : Uint4B
#    +0xf9c IsImpersonating  : Uint4B
#    +0xfa0 NlsCache         : Ptr32 Void
#    +0xfa4 pShimData        : Ptr32 Void
#    +0xfa8 HeapVirtualAffinity : Uint4B
#    +0xfac CurrentTransactionHandle : Ptr32 Void
#    +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
#    +0xfb4 FlsData          : Ptr32 Void
#    +0xfb8 PreferredLanguages : Ptr32 Void
#    +0xfbc UserPrefLanguages : Ptr32 Void
#    +0xfc0 MergedPrefLanguages : Ptr32 Void
#    +0xfc4 MuiImpersonation : Uint4B
#    +0xfc8 CrossTebFlags    : Uint2B
#    +0xfc8 SpareCrossTebBits : Pos 0, 16 Bits
#    +0xfca SameTebFlags     : Uint2B
#    +0xfca DbgSafeThunkCall : Pos 0, 1 Bit
#    +0xfca DbgInDebugPrint  : Pos 1, 1 Bit
#    +0xfca DbgHasFiberData  : Pos 2, 1 Bit
#    +0xfca DbgSkipThreadAttach : Pos 3, 1 Bit
#    +0xfca DbgWerInShipAssertCode : Pos 4, 1 Bit
#    +0xfca DbgRanProcessInit : Pos 5, 1 Bit
#    +0xfca DbgClonedThread  : Pos 6, 1 Bit
#    +0xfca DbgSuppressDebugMsg : Pos 7, 1 Bit
#    +0xfca RtlDisableUserStackWalk : Pos 8, 1 Bit
#    +0xfca RtlExceptionAttached : Pos 9, 1 Bit
#    +0xfca SpareSameTebBits : Pos 10, 6 Bits
#    +0xfcc TxnScopeEnterCallback : Ptr32 Void
#    +0xfd0 TxnScopeExitCallback : Ptr32 Void
#    +0xfd4 TxnScopeContext  : Ptr32 Void
#    +0xfd8 LockCount        : Uint4B
#    +0xfdc ProcessRundown   : Uint4B
#    +0xfe0 LastSwitchTime   : Uint8B
#    +0xfe8 TotalSwitchOutTime : Uint8B
#    +0xff0 WaitReasonBitMap : _LARGE_INTEGER

# TODO
# Break down the TEB into multiple structures, once for each Windows version.
# Then autodetect the current Windows version and set the TEB symbol to the
# correct structure (while keeping the others for reference).
class TEB(Structure):
    _pack_ = 1
    _fields_ = [

        # Windows NT (maybe 2000)

        ("NtTib",                           NT_TIB),
        ("EnvironmentPointer",              PVOID),
        ("ClientId",                        CLIENT_ID),
        ("ActiveRpcHandle",                 PVOID),
        ("ThreadLocalStoragePointer",       PVOID),
        ("ProcessEnvironmentBlock",         PPEB),
        ("LastErrorValue",                  ULONG),
        ("CountOfOwnedCriticalSections",    ULONG),
        ("CsrClientThread",                 PVOID),
        ("Win32ThreadInfo",                 PVOID),
        ("User32Reserved",                  ULONG * 26),
        ("UserReserved",                    ULONG * 5),
        ("WOW32Reserved",                   PVOID),
        ("CurrentLocale",                   ULONG),
        ("FpSoftwareStatusRegister",        ULONG),
        ("SystemReserved1",                 PVOID * 54),
        ("Spare1",                          PVOID),
        ("ExceptionCode",                   ULONG),
        ("ActivationContextStackPointer",   PVOID), # PACTIVATION_CONTEXT_STACK
        ("SpareBytes1",                     ULONG * 36),
        ("TxFsContext",                     ULONG),
        ("GdiTebBatch",                     GDI_TEB_BATCH),
        ("RealClientId",                    CLIENT_ID),
        ("GdiCachedProcessHandle",          PVOID),
        ("GdiClientPID",                    ULONG),
        ("GdiClientTID",                    ULONG),
        ("GdiThreadLocalInfo",              PVOID),
        ("Win32ClientInfo",                 PVOID * 62),
        ("glDispatchTable",                 PVOID * 233),
        ("glReserved1",                     ULONG * 29),
        ("glReserved2",                     PVOID),
        ("glSectionInfo",                   PVOID),
        ("glSection",                       PVOID),
        ("glTable",                         PVOID),
        ("glCurrentRC",                     PVOID),
        ("glContext",                       PVOID),
        ("LastStatusValue",                 NTSTATUS),
        ("StaticUnicodeString",             UNICODE_STRING),
        ("StaticUnicodeBuffer",             WCHAR * 261),
        ("DeallocationStack",               PVOID),
        ("TlsSlots",                        PVOID * 64),
        ("TlsLinks",                        LIST_ENTRY),
        ("Vdm",                             PVOID),
        ("ReservedForNtRpc",                PVOID),
        ("DbgSsReserved",                   PVOID * 2),
        ("HardErrorDisabled",               ULONG),
        ("Instrumentation",                 PVOID * 9),
        ("ActivityId",                      GUID),
        ("SubProcessTag",                   PVOID),
        ("EtwLocalData",                    PVOID),
        ("EtwTraceData",                    PVOID),
        ("WinSockData",                     PVOID),
        ("GdiBatchCount",                   ULONG),
        ("SpareBool0",                      UCHAR),
        ("SpareBool1",                      UCHAR),
        ("SpareBool2",                      UCHAR),
        ("IdealProcessor",                  UCHAR),
        ("GuaranteedStackBytes",            ULONG),
        ("ReservedForPerf",                 PVOID),
        ("ReservedForOle",                  PVOID),
        ("WaitingOnLoaderLock",             ULONG),

        # Windows NT only I believe???
##        ("StackCommit",                     PVOID),
##        ("StackCommitMax",                  PVOID),
##        ("StackReserved",                   PVOID),

        # TODO
        # Add more fields here

##        +0xf88 SavedPriorityState : Ptr32 Void
##        +0xf8c SoftPatchPtr1    : Uint4B
##        +0xf90 ThreadPoolData   : Ptr32 Void
##        +0xf94 TlsExpansionSlots : Ptr32 Ptr32 Void
##        +0xf98 ImpersonationLocale : Uint4B
##        +0xf9c IsImpersonating  : Uint4B
##        +0xfa0 NlsCache         : Ptr32 Void
##        +0xfa4 pShimData        : Ptr32 Void
##        +0xfa8 HeapVirtualAffinity : Uint4B
##        +0xfac CurrentTransactionHandle : Ptr32 Void
##        +0xfb0 ActiveFrame      : Ptr32 _TEB_ACTIVE_FRAME
##        +0xfb4 FlsData          : Ptr32 Void
##        +0xfb8 PreferredLanguages : Ptr32 Void
##        +0xfbc UserPrefLanguages : Ptr32 Void
##        +0xfc0 MergedPrefLanguages : Ptr32 Void
##        +0xfc4 MuiImpersonation : Uint4B
##        +0xfc8 CrossTebFlags    : Uint2B
##        +0xfc8 SpareCrossTebBits : Pos 0, 16 Bits
##        +0xfca SameTebFlags     : Uint2B
##        +0xfca DbgSafeThunkCall : Pos 0, 1 Bit
##        +0xfca DbgInDebugPrint  : Pos 1, 1 Bit
##        +0xfca DbgHasFiberData  : Pos 2, 1 Bit
##        +0xfca DbgSkipThreadAttach : Pos 3, 1 Bit
##        +0xfca DbgWerInShipAssertCode : Pos 4, 1 Bit
##        +0xfca DbgRanProcessInit : Pos 5, 1 Bit
##        +0xfca DbgClonedThread  : Pos 6, 1 Bit
##        +0xfca DbgSuppressDebugMsg : Pos 7, 1 Bit
##        +0xfca RtlDisableUserStackWalk : Pos 8, 1 Bit
##        +0xfca RtlExceptionAttached : Pos 9, 1 Bit
##        +0xfca SpareSameTebBits : Pos 10, 6 Bits
##        +0xfcc TxnScopeEnterCallback : Ptr32 Void
##        +0xfd0 TxnScopeExitCallback : Ptr32 Void
##        +0xfd4 TxnScopeContext  : Ptr32 Void
##        +0xfd8 LockCount        : Uint4B
##        +0xfdc ProcessRundown   : Uint4B
##        +0xfe0 LastSwitchTime   : Uint8B
##        +0xfe8 TotalSwitchOutTime : Uint8B
##        +0xff0 WaitReasonBitMap : _LARGE_INTEGER
]

# From MSDN:
#
# typedef struct _PROCESS_BASIC_INFORMATION {
#     PVOID Reserved1;
#     PPEB PebBaseAddress;
#     PVOID Reserved2[2];
#     ULONG_PTR UniqueProcessId;
#     PVOID Reserved3;
# } PROCESS_BASIC_INFORMATION;
##class PROCESS_BASIC_INFORMATION(Structure):
##    _fields_ = [
##        ("Reserved1",       PVOID),
##        ("PebBaseAddress",  PPEB),
##        ("Reserved2",       PVOID * 2),
##        ("UniqueProcessId", ULONG_PTR),
##        ("Reserved3",       PVOID),
##]

# From http://catch22.net/tuts/tips2
#
# typedef struct
# {
#     ULONG      ExitStatus;
#     PVOID      PebBaseAddress;
#     ULONG      AffinityMask;
#     ULONG      BasePriority;
#     ULONG_PTR  UniqueProcessId;
#     ULONG_PTR  InheritedFromUniqueProcessId;
# } PROCESS_BASIC_INFORMATION;
class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus",                      ULONG),
        ("PebBaseAddress",                  PVOID),
        ("AffinityMask",                    ULONG),
        ("BasePriority",                    ULONG),
        ("UniqueProcessId",                 ULONG_PTR),
        ("InheritedFromUniqueProcessId",    ULONG_PTR),
]

# From http://undocumented.ntinternals.net/UserMode/Structures/THREAD_BASIC_INFORMATION.html
#
# typedef struct _THREAD_BASIC_INFORMATION {
#   NTSTATUS ExitStatus;
#   PVOID TebBaseAddress;
#   CLIENT_ID ClientId;
#   KAFFINITY AffinityMask;
#   KPRIORITY Priority;
#   KPRIORITY BasePriority;
# } THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

##PTEB = POINTER(TEB)
PTEB = PVOID

class THREAD_BASIC_INFORMATION(Structure):
    _fields_ = [
        ("ExitStatus",      NTSTATUS),
        ("TebBaseAddress",  PTEB),
        ("ClientId",        CLIENT_ID),
        ("AffinityMask",    KAFFINITY),
        ("Priority",        KPRIORITY),
        ("BasePriority",    KPRIORITY),
]

#--- SYSDBG_MSR structure and constants ---------------------------------------

SysDbgReadMsr  = 16
SysDbgWriteMsr = 17

class SYSDBG_MSR(Structure):
    _fields_ = [
        ("Address", ULONG),
        ("Data",    ULONGLONG),
]

#--- IO_STATUS_BLOCK structure ------------------------------------------------

# typedef struct _IO_STATUS_BLOCK {
#     union {
#         NTSTATUS Status;
#         PVOID Pointer;
#     };
#     ULONG_PTR Information;
# } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
class IO_STATUS_BLOCK(Structure):
    _fields_ = [
        ("Status",      NTSTATUS),
        ("Information", ULONG_PTR),
    ]
    @property
    def Pointer(self):
        return PVOID(self.Status)

#--- ntdll.dll ----------------------------------------------------------------

# NTSYSAPI NTSTATUS NTAPI NtSystemDebugControl(
#   IN SYSDBG_COMMAND Command,
#   IN PVOID InputBuffer OPTIONAL,
#   IN ULONG InputBufferLength,
#   OUT PVOID OutputBuffer OPTIONAL,
#   IN ULONG OutputBufferLength,
#   OUT PULONG ReturnLength OPTIONAL
# );
def NtSystemDebugControl(Command, InputBuffer = None, InputBufferLength = None, OutputBuffer = None, OutputBufferLength = None):
    if InputBuffer is None:
        InputBuffer = NULL
    if InputBufferLength is None:
        if InputBuffer == NULL:
            InputBufferLength = 0
        else:
            InputBufferLength = sizeof(InputBuffer)
    if OutputBuffer is None:
        if OutputBufferLength is None:
            OutputBuffer       = NULL
            OutputBufferLength = 0
        else:
            OutputBuffer = ctypes.create_string_buffer("", OutputBufferLength)
    elif OutputBufferLength is None:
        OutputBufferLength = sizeof(OutputBuffer)
    if InputBuffer != NULL:
        InputBuffer = ctypes.byref(InputBuffer)
    if OutputBuffer != NULL:
        OutputBuffer = ctypes.byref(OutputBuffer)
    ReturnLength = ULONG(0)
    ntstatus = ctypes.windll.ntdll.NtSystemDebugControl(Command, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, ctypes.byref(ReturnLength))
    if ntstatus != 0:
        raise ctypes.WinError(ntstatus) # ^ 0xFFFFFFFF)
    return OutputBuffer, ReturnLength.value
ZwSystemDebugControl = NtSystemDebugControl

# NTSTATUS WINAPI NtQueryInformationProcess(
#   __in       HANDLE ProcessHandle,
#   __in       PROCESSINFOCLASS ProcessInformationClass,
#   __out      PVOID ProcessInformation,
#   __in       ULONG ProcessInformationLength,
#   __out_opt  PULONG ReturnLength
# );
def NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformationLength = None):
    if ProcessInformationLength is not None:
        ProcessInformation = ctypes.create_string_buffer("", ProcessInformationLength)
    else:
        if   ProcessInformationClass == ProcessBasicInformation:
            ProcessInformation = PROCESS_BASIC_INFORMATION()
            ProcessInformationLength = sizeof(PROCESS_BASIC_INFORMATION)
        elif ProcessInformationClass == ProcessImageFileName:
            unicode_buffer = ctypes.create_unicode_buffer(u"", 0x1000)
            ProcessInformation = UNICODE_STRING(0, 0x1000, ctypes.addressof(unicode_buffer))
            ProcessInformationLength = sizeof(UNICODE_STRING)
        elif ProcessInformationClass in (ProcessDebugPort, ProcessWow64Information, ProcessWx86Information, ProcessHandleCount, ProcessPriorityBoost):
            ProcessInformation = DWORD()
            ProcessInformationLength = sizeof(DWORD)
        else:
            raise Exception, "Unknown ProcessInformationClass, use an explicit ProcessInformationLength value instead"
    ReturnLength = ULONG(0)
    ProcessHandle = HANDLE(ProcessHandle)
    ntstatus = ctypes.windll.ntdll.NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ctypes.byref(ProcessInformation), ProcessInformationLength, ctypes.byref(ReturnLength))
    if ntstatus != 0:
        raise ctypes.WinError(ntstatus) # ^ 0xFFFFFFFF)
    if   ProcessInformationClass == ProcessBasicInformation:
        retval = ProcessInformation
    elif ProcessInformationClass in (ProcessDebugPort, ProcessWow64Information, ProcessWx86Information, ProcessHandleCount, ProcessPriorityBoost):
        retval = ProcessInformation.value
    elif ProcessInformationClass == ProcessImageFileName:
        vptr = ctypes.c_void_p(ProcessInformation.Buffer)
        cptr = ctypes.cast( vptr, ctypes.c_wchar * ProcessInformation.Length )
        retval = cptr.contents.raw
    else:
        retval = ProcessInformation.raw[:ReturnLength.value]
    return retval
ZwQueryInformationProcess = NtQueryInformationProcess

# NTSTATUS WINAPI NtQueryInformationThread(
#   __in       HANDLE ThreadHandle,
#   __in       THREADINFOCLASS ThreadInformationClass,
#   __out      PVOID ThreadInformation,
#   __in       ULONG ThreadInformationLength,
#   __out_opt  PULONG ReturnLength
# );
def NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformationLength = None):
    if ThreadInformationLength is not None:
        ThreadInformation = ctypes.create_string_buffer("", ThreadInformationLength)
    else:
        if   ThreadInformationClass == ThreadBasicInformation:
            ThreadInformation = THREAD_BASIC_INFORMATION()
            ThreadInformationLength = sizeof(THREAD_BASIC_INFORMATION)
        elif ThreadInformationClass in (ThreadQuerySetWin32StartAddress, ThreadAmILastThread, ThreadPriorityBoost, ThreadHideFromDebugger):
            ThreadInformation = DWORD()
            ThreadInformationLength = sizeof(DWORD)
        elif ThreadInformationClass == ThreadPerformanceCount:
            ThreadInformation = LONGLONG()  # LARGE_INTEGER
            ThreadInformationLength = sizeof(LONGLONG)
        else:
            raise Exception, "Unknown ThreadInformationClass, use an explicit ThreadInformationLength value instead"
    ReturnLength = ULONG(0)
    ThreadHandle = HANDLE(ThreadHandle)
    ntstatus = ctypes.windll.ntdll.NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ctypes.byref(ThreadInformation), ThreadInformationLength, ctypes.byref(ReturnLength))
    if ntstatus != 0:
        raise ctypes.WinError(ntstatus) # ^ 0xFFFFFFFF)
    if   ThreadInformationClass == ThreadBasicInformation:
        retval = ThreadInformation
    elif ThreadInformationClass in (ThreadQuerySetWin32StartAddress, ThreadAmILastThread, ThreadPriorityBoost, ThreadHideFromDebugger):
        retval = ThreadInformation.value
    elif ThreadInformationClass == ThreadPerformanceCount:
        retval = ThreadInformation.value
    else:
        retval = ThreadInformation.raw[:ReturnLength.value]
    return retval
ZwQueryInformationThread = NtQueryInformationThread

# NTSTATUS
#   NtQueryInformationFile(
#     IN HANDLE  FileHandle,
#     OUT PIO_STATUS_BLOCK  IoStatusBlock,
#     OUT PVOID  FileInformation,
#     IN ULONG  Length,
#     IN FILE_INFORMATION_CLASS  FileInformationClass
#     );
def NtQueryInformationFile(FileHandle, FileInformationClass, FileInformation, Length):
    IoStatusBlock = IO_STATUS_BLOCK()
    FileHandle = HANDLE(FileHandle)
    status = NtQueryInformationFile(FileHandle, ctypes.byref(IoStatusBlock), ctypes.byref(FileInformation), Length, FileInformationClass)
    if status != 0:
        raise ctypes.WinError(ntstatus) # ^ 0xFFFFFFFF)
    return IoStatusBlock.Information
ZwQueryInformationFile = NtQueryInformationFile
