#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2012, Mario Vilas
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
Wrapper for shell32.dll in ctypes.
"""

# TODO
# * Add a class wrapper to SHELLEXECUTEINFO
# * More logic into ShellExecuteEx

__revision__ = "$Id$"

from defines import *
from kernel32 import LocalFree

#--- Constants ----------------------------------------------------------------

SEE_MASK_DEFAULT            = 0x00000000
SEE_MASK_CLASSNAME          = 0x00000001
SEE_MASK_CLASSKEY           = 0x00000003
SEE_MASK_IDLIST             = 0x00000004
SEE_MASK_INVOKEIDLIST       = 0x0000000C
SEE_MASK_ICON               = 0x00000010
SEE_MASK_HOTKEY             = 0x00000020
SEE_MASK_NOCLOSEPROCESS     = 0x00000040
SEE_MASK_CONNECTNETDRV      = 0x00000080
SEE_MASK_NOASYNC            = 0x00000100
SEE_MASK_DOENVSUBST         = 0x00000200
SEE_MASK_FLAG_NO_UI         = 0x00000400
SEE_MASK_UNICODE            = 0x00004000
SEE_MASK_NO_CONSOLE         = 0x00008000
SEE_MASK_ASYNCOK            = 0x00100000
SEE_MASK_HMONITOR           = 0x00200000
SEE_MASK_NOZONECHECKS       = 0x00800000
SEE_MASK_WAITFORINPUTIDLE   = 0x02000000
SEE_MASK_FLAG_LOG_USAGE     = 0x04000000

SE_ERR_FNF              = 2
SE_ERR_PNF              = 3
SE_ERR_ACCESSDENIED     = 5
SE_ERR_OOM              = 8
SE_ERR_DLLNOTFOUND      = 32
SE_ERR_SHARE            = 26
SE_ERR_ASSOCINCOMPLETE  = 27
SE_ERR_DDETIMEOUT       = 28
SE_ERR_DDEFAIL          = 29
SE_ERR_DDEBUSY          = 30
SE_ERR_NOASSOC          = 31

#--- Structures ---------------------------------------------------------------

# typedef struct _SHELLEXECUTEINFO {
#   DWORD     cbSize;
#   ULONG     fMask;
#   HWND      hwnd;
#   LPCTSTR   lpVerb;
#   LPCTSTR   lpFile;
#   LPCTSTR   lpParameters;
#   LPCTSTR   lpDirectory;
#   int       nShow;
#   HINSTANCE hInstApp;
#   LPVOID    lpIDList;
#   LPCTSTR   lpClass;
#   HKEY      hkeyClass;
#   DWORD     dwHotKey;
#   union {
#     HANDLE hIcon;
#     HANDLE hMonitor;
#   } DUMMYUNIONNAME;
#   HANDLE    hProcess;
# } SHELLEXECUTEINFO, *LPSHELLEXECUTEINFO;

class SHELLEXECUTEINFO(Structure):
    _fields_ = [
        ("cbSize",       DWORD),
        ("fMask",        ULONG),
        ("hwnd",         HWND),
        ("lpVerb",       LPSTR),
        ("lpFile",       LPSTR),
        ("lpParameters", LPSTR),
        ("lpDirectory",  LPSTR),
        ("nShow",        ctypes.c_int),
        ("hInstApp",     HINSTANCE),
        ("lpIDList",     LPVOID),
        ("lpClass",      LPSTR),
        ("hkeyClass",    HKEY),
        ("dwHotKey",     DWORD),
        ("hIcon",        HANDLE),
        ("hProcess",     HANDLE),
    ]

    def __get_hMonitor(self):
        return self.hIcon
    def __set_hMonitor(self, hMonitor):
        self.hIcon = hMonitor
    hMonitor = property(__get_hMonitor, __set_hMonitor)

LPSHELLEXECUTEINFO = POINTER(SHELLEXECUTEINFO)

#--- shell32.dll --------------------------------------------------------------

# LPWSTR *CommandLineToArgvW(
#     LPCWSTR lpCmdLine,
#     int *pNumArgs
# );
def CommandLineToArgvW(lpCmdLine):
    _CommandLineToArgvW = windll.shell32.CommandLineToArgvW
    _CommandLineToArgvW.argtypes = [LPVOID, POINTER(ctypes.c_int)]
    _CommandLineToArgvW.restype  = LPVOID

    if not lpCmdLine:
        lpCmdLine = None
    argc = ctypes.c_int(0)
    vptr = ctypes.windll.shell32.CommandLineToArgvW(lpCmdLine, byref(argc))
    if vptr == NULL:
        raise ctypes.WinError()
    argv = vptr
    try:
        argc = argc.value
        if argc <= 0:
            raise ctypes.WinError()
        argv = ctypes.cast(argv, ctypes.POINTER(LPWSTR * argc) )
        argv = [ argv.contents[i] for i in xrange(0, argc) ]
    finally:
        if vptr is not None:
            LocalFree(vptr)
    return argv

def CommandLineToArgvA(lpCmdLine):
    t_ansi = GuessStringType.t_ansi
    t_unicode = GuessStringType.t_unicode
    if isinstance(lpCmdLine, t_ansi):
        cmdline = t_unicode(lpCmdLine)
    else:
        cmdline = lpCmdLine
    return [t_ansi(x) for x in CommandLineToArgvW(cmdline)]

CommandLineToArgv = GuessStringType(CommandLineToArgvA, CommandLineToArgvW)

# HINSTANCE ShellExecute(
#     HWND hwnd,
#     LPCTSTR lpOperation,
#     LPCTSTR lpFile,
#     LPCTSTR lpParameters,
#     LPCTSTR lpDirectory,
#     INT nShowCmd
# );
def ShellExecuteA(hwnd = None, lpOperation = None, lpFile = None, lpParameters = None, lpDirectory = None, nShowCmd = None):
    _ShellExecuteA = windll.shell32.ShellExecuteA
    _ShellExecuteA.argtypes = [HWND, LPSTR, LPSTR, LPSTR, LPSTR, INT]
    _ShellExecuteA.restype  = HINSTANCE

    if not nShowCmd:
        nShowCmd = 0
    success = _ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    success = ctypes.cast(success, c_int)
    success = success.value
    if not success > 32:    # weird! isn't it?
        raise ctypes.WinError(success)

def ShellExecuteW(hwnd = None, lpOperation = None, lpFile = None, lpParameters = None, lpDirectory = None, nShowCmd = None):
    _ShellExecuteW = windll.shell32.ShellExecuteW
    _ShellExecuteW.argtypes = [HWND, LPWSTR, LPWSTR, LPWSTR, LPWSTR, INT]
    _ShellExecuteW.restype  = HINSTANCE

    if not nShowCmd:
        nShowCmd = 0
    success = _ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    success = ctypes.cast(success, c_int)
    success = success.value
    if not success > 32:    # weird! isn't it?
        raise ctypes.WinError(success)

ShellExecute = GuessStringType(ShellExecuteA, ShellExecuteW)

# BOOL ShellExecuteEx(
#   __inout  LPSHELLEXECUTEINFO lpExecInfo
# );
def ShellExecuteEx(lpExecInfo):
    if isinstance(lpExecInfo, SHELLEXECUTEINFOA):
        ShellExecuteExA(lpExecInfo)
    elif isinstance(lpExecInfo, SHELLEXECUTEINFOW):
        ShellExecuteExW(lpExecInfo)
    else:
        raise TypeError("Expected SHELLEXECUTEINFOA or SHELLEXECUTEINFOW, got %s instead" % type(lpExecInfo))

def ShellExecuteExA(lpExecInfo):
    _ShellExecuteExA = windll.shell32.ShellExecuteExA
    _ShellExecuteExA.argtypes = [LPSHELLEXECUTEINFOA]
    _ShellExecuteExA.restype  = BOOL
    _ShellExecuteExA.errcheck = RaiseIfZero
    _ShellExecuteExA(byref(lpExecInfo))

def ShellExecuteExW(lpExecInfo):
    _ShellExecuteExW = windll.shell32.ShellExecuteExW
    _ShellExecuteExW.argtypes = [LPSHELLEXECUTEINFOW]
    _ShellExecuteExW.restype  = BOOL
    _ShellExecuteExW.errcheck = RaiseIfZero
    _ShellExecuteExW(byref(lpExecInfo))
