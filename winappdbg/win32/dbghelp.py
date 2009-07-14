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
from kernel32 import *

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

#--- dbghelp.dll --------------------------------------------------------------

# XXX the ANSI versions of these functions don't end in "A" as expected!

# BOOL WINAPI SymInitialize(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR UserSearchPath,
#   __in      BOOL fInvadeProcess
# );
def SymInitialize(hProcess, UserSearchPath = None, fInvadeProcess = False):
    if not UserSearchPath:
        UserSearchPath = LPVOID(NULL)
    else:
        UserSearchPath = ctypes.create_string_buffer(UserSearchPath)
        UserSearchPath = ctypes.byref(UserSearchPath)
    if fInvadeProcess:
        fInvadeProcess = TRUE
    else:
        fInvadeProcess = FALSE
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymInitialize(hProcess, UserSearchPath, fInvadeProcess)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI SymCleanup(
#   __in  HANDLE hProcess
# );
def SymCleanup(hProcess):
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymCleanup(hProcess)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI SymRefreshModuleList(
#   __in  HANDLE hProcess
# );
def SymRefreshModuleList(hProcess):
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymRefreshModuleList(hProcess)
    if success == FALSE:
        raise ctypes.WinError()

# BOOL WINAPI SymSetParentWindow(
#   __in  HWND hwnd
# );
def SymSetParentWindow(hwnd):
    hwnd = HWND(hwnd)
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
        hFile = LPVOID(NULL)
    else:
        hFile = HANDLE(hFile)
    if not ImageName:
        ImageName = LPVOID(NULL)
    else:
        ImageName = ctypes.create_string_buffer(ImageName)
        ImageName = ctypes.byref(ImageName)
    if not ModuleName:
        ModuleName = LPVOID(NULL)
    else:
        ModuleName = ctypes.create_string_buffer(ModuleName)
        ModuleName = ctypes.byref(ModuleName)
    if not BaseOfDll:
        BaseOfDll = LPVOID(NULL)
    else:
        BaseOfDll = LPVOID(BaseOfDll)
    if not SizeOfDll:
        SizeOfDll = 0
    hProcess = HANDLE(hProcess)
    SymLoadModule = ctypes.windll.dbghelp.SymLoadModule
    SymLoadModule.restype = LPVOID
    lpBaseAddress = SymLoadModule(hProcess, hFile, ImageName, ModuleName, BaseOfDll, SizeOfDll)
    lpBaseAddress = lpBaseAddress.value
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
    hProcess = HANDLE(hProcess)
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
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymGetModuleInfo(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    if success == FALSE:
        raise ctypes.WinError()
    return ModuleInfo
def SymGetModuleInfoW(hProcess, dwAddr):
    ModuleInfo = IMAGEHLP_MODULEW()
    ModuleInfo.SizeOfStruct = ctypes.sizeof(ModuleInfo)
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymGetModuleInfoW(hProcess, dwAddr, ctypes.byref(ModuleInfo))
    if success == FALSE:
        raise ctypes.WinError()
    return ModuleInfo
SymGetModuleInfo = GuessStringType(SymGetModuleInfoA, SymGetModuleInfoW)

# BOOL CALLBACK SymEnumerateModulesProc64(
#   __in      PCTSTR ModuleName,
#   __in      DWORD64 BaseOfDll,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMMODULES_CALLBACK    = WINFUNCTYPE(BOOL, ctypes.POINTER(CHAR),  DWORD,   PVOID)
PSYM_ENUMMODULES_CALLBACKW   = WINFUNCTYPE(BOOL, ctypes.POINTER(WCHAR), DWORD,   PVOID)
PSYM_ENUMMODULES_CALLBACK64  = WINFUNCTYPE(BOOL, ctypes.POINTER(CHAR),  DWORD64, PVOID)
PSYM_ENUMMODULES_CALLBACKW64 = WINFUNCTYPE(BOOL, ctypes.POINTER(WCHAR), DWORD64, PVOID)

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
        UserContext = LPVOID(NULL)
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymEnumerateModules(hProcess, BaseOfDll, EnumModulesCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
def SymEnumerateModulesW(hProcess, BaseOfDll, EnumModulesCallback, UserContext = None):
    EnumModulesCallback = PSYM_ENUMMODULES_CALLBACKW(EnumModulesCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymEnumerateModulesW(hProcess, BaseOfDll, EnumModulesCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
SymEnumerateModules = GuessStringType(SymEnumerateModulesA, SymEnumerateModulesW)

# BOOL CALLBACK SymEnumerateSymbolsProc64(
#   __in      PCTSTR SymbolName,
#   __in      DWORD64 SymbolAddress,
#   __in      ULONG SymbolSize,
#   __in_opt  PVOID UserContext
# );
PSYM_ENUMSYMBOLS_CALLBACK    = WINFUNCTYPE(BOOL, ctypes.c_char_p,  DWORD,   ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW   = WINFUNCTYPE(BOOL, ctypes.c_wchar_p, DWORD,   ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACK64  = WINFUNCTYPE(BOOL, ctypes.c_char_p,  DWORD64, ULONG, PVOID)
PSYM_ENUMSYMBOLS_CALLBACKW64 = WINFUNCTYPE(BOOL, ctypes.c_wchar_p, DWORD64, ULONG, PVOID)

# BOOL WINAPI SymEnumerateSymbols(
#   __in      HANDLE hProcess,
#   __in      ULONG BaseOfDll,
#   __in      PSYM_ENUMSYMBOLS_CALLBACK EnumSymbolsCallback,
#   __in_opt  PVOID UserContext
# );
def SymEnumerateSymbolsA(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACK(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymEnumerateSymbols(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
def SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext = None):
    EnumSymbolsCallback = PSYM_ENUMSYMBOLS_CALLBACKW(EnumSymbolsCallback)
    if UserContext:
        UserContext = ctypes.pointer(UserContext)
    else:
        UserContext = LPVOID(NULL)
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymEnumerateSymbolsW(hProcess, BaseOfDll, EnumSymbolsCallback, UserContext)
    if success == FALSE:
        raise ctypes.WinError()
SymEnumerateSymbols = GuessStringType(SymEnumerateSymbolsA, SymEnumerateSymbolsW)

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
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymGetSearchPath(hProcess, SearchPath, SearchPathLength)
    if success == FALSE:
        raise ctypes.WinError()
    return SearchPath.value
def SymGetSearchPathW(hProcess):
    SearchPathLength = MAX_PATH
    SearchPath = ctypes.byref(ctypes.create_unicode_buffer("", SearchPathLength))
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymGetSearchPathW(hProcess, SearchPath, SearchPathLength)
    if success == FALSE:
        raise ctypes.WinError()
    return SearchPath.value
SymGetSearchPath = GuessStringType(SymGetSearchPathA, SymGetSearchPathW)

# BOOL WINAPI SymSetSearchPath(
#   __in      HANDLE hProcess,
#   __in_opt  PCTSTR SearchPath
# );
def SymSetSearchPathA(hProcess, SearchPath = None):
    if SearchPath:
        SearchPath = ctypes.byref(ctypes.create_string_buffer(SearchPath))
    else:
        SearchPath = LPVOID(NULL)
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymSetSearchPath(hProcess, SearchPath)
    if success == FALSE:
        raise ctypes.WinError()
def SymSetSearchPathW(hProcess, SearchPath = None):
    if SearchPath:
        SearchPath = ctypes.byref(ctypes.create_unicode_buffer(SearchPath))
    else:
        SearchPath = LPVOID(NULL)
    hProcess = HANDLE(hProcess)
    success = ctypes.windll.dbghelp.SymSetSearchPathW(hProcess, SearchPath)
    if success == FALSE:
        raise ctypes.WinError()
SymSetSearchPath = GuessStringType(SymSetSearchPathA, SymSetSearchPathW)
