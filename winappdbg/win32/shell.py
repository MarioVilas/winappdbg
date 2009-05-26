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
Shell API.
"""

__revision__ = "$Id$"

from kernel import *

#--- Functions ----------------------------------------------------------------

# LPWSTR *CommandLineToArgvW(
#     LPCWSTR lpCmdLine,
#     int *pNumArgs
# );
def CommandLineToArgvW(lpCmdLine):
    if lpCmdLine is None:
        lpCmdLine = NULL
    argc = ctypes.c_int(0)
    argv = ctypes.windll.shell32.CommandLineToArgvW(lpCmdLine, ctypes.byref(argc))
    if argv == NULL or argc.value <= 0:
        ctypes.WinError()
    try:
        vptr = ctypes.c_void_p(argv)
        aptr = ctypes.cast(vptr, ctypes.POINTER(ctypes.c_wchar_p * argc.value) )
        argv = [ aptr.contents[i] for i in xrange(0, argc.value) ]
    finally:
        LocalFree(vptr)
    return argv
def CommandLineToArgvA(lpCmdLine):
    if lpCmdLine not in (None, NULL):
        lpCmdLine = unicode(lpCmdLine)
    argv = CommandLineToArgvW(lpCmdLine)
    argv = [ str(x) for x in argv ]
    return argv
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
    if not hwnd:
        hwnd = NULL
    if not lpOperation:
        lpOperation = NULL
    if not lpFile:
        lpFile = NULL
    if not lpParameters:
        lpParameters = NULL
    if not lpDirectory:
        lpDirectory = NULL
    if not nShowCmd:
        nShowCmd = 0
    success = ctypes.windll.shell32.ShellExecuteA(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    if success != 0:
        ctypes.WinError(success)
def ShellExecuteW(hwnd = None, lpOperation = None, lpFile = None, lpParameters = None, lpDirectory = None, nShowCmd = None):
    if not hwnd:
        hwnd = NULL
    if not lpOperation:
        lpOperation = NULL
    if not lpFile:
        lpFile = NULL
    if not lpParameters:
        lpParameters = NULL
    if not lpDirectory:
        lpDirectory = NULL
    if not nShowCmd:
        nShowCmd = 0
    success = ctypes.windll.shell32.ShellExecuteW(hwnd, lpOperation, lpFile, lpParameters, lpDirectory, nShowCmd)
    if success != 0:
        ctypes.WinError(success)
ShellExecute = ShellExecuteA
