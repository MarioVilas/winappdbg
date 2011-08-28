# Copyright (c) 2009-2011, Mario Vilas
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

__revision__ = "$Id$"

from defines import *
from kernel32 import LocalFree

#--- shell32.dll --------------------------------------------------------------

# LPWSTR *CommandLineToArgvW(
#     LPCWSTR lpCmdLine,
#     int *pNumArgs
# );
def CommandLineToArgvW(lpCmdLine):
    _CommandLineToArgvW = windll.shell32.CommandLineToArgvW
    _CommandLineToArgvW.argtypes = [LPVOID, POINTER(ctypes.c_int)]
    _CommandLineToArgvW.restype = LPVOID

    if not lpCmdLine:
        lpCmdLine = None
    argc = ctypes.c_int(0)
    vptr = ctypes.windll.shell32.CommandLineToArgvW(lpCmdLine, ctypes.byref(argc))
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

CommandLineToArgvA = MakeANSIVersion(CommandLineToArgvW)
CommandLineToArgv = CommandLineToArgvA

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
    _ShellExecuteA.restype = HINSTANCE

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
    _ShellExecuteW.restype = HINSTANCE

    if not nShowCmd:
        nShowCmd = 0
    success = _ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    success = ctypes.cast(success, c_int)
    success = success.value
    if not success > 32:    # weird! isn't it?
        raise ctypes.WinError(success)

ShellExecute = GuessStringType(ShellExecuteA, ShellExecuteW)
