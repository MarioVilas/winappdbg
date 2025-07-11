#!/usr/bin/python3
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

from winappdbg.debug import Debug
from winappdbg.event import EventHandler
from winappdbg.win32 import DWORD, HANDLE, HKEY, PVOID, REGSAM


class MyEventHandler(EventHandler):
    # Here we set which API calls we want to intercept.
    apiHooks = {
        # Hooks for the kernel32 library.
        "kernel32.dll": [
            #  Function            Parameters
            ("CreateFileA", (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),
            ("CreateFileW", (PVOID, DWORD, DWORD, PVOID, DWORD, DWORD, HANDLE)),
        ],
        # Hooks for the advapi32 library.
        "advapi32.dll": [
            #  Function            Parameters
            (
                "RegCreateKeyExA",
                (HKEY, PVOID, DWORD, PVOID, DWORD, REGSAM, PVOID, PVOID, PVOID),
            ),
            (
                "RegCreateKeyExW",
                (HKEY, PVOID, DWORD, PVOID, DWORD, REGSAM, PVOID, PVOID, PVOID),
            ),
        ],
    }

    # Now we can simply define a method for each hooked API.
    # Methods beginning with "pre_" are called when entering the API,
    # and methods beginning with "post_" when returning from the API.

    def pre_CreateFileA(
        self,
        event,
        ra,
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    ):
        self.__print_opening_ansi(event, "file", lpFileName)

    def pre_CreateFileW(
        self,
        event,
        ra,
        lpFileName,
        dwDesiredAccess,
        dwShareMode,
        lpSecurityAttributes,
        dwCreationDisposition,
        dwFlagsAndAttributes,
        hTemplateFile,
    ):
        self.__print_opening_unicode(event, "file", lpFileName)

    def pre_RegCreateKeyExA(
        self,
        event,
        ra,
        hKey,
        lpSubKey,
        Reserved,
        lpClass,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition,
    ):
        self.__print_opening_ansi(event, "key", lpSubKey)

    def pre_RegCreateKeyExW(
        self,
        event,
        ra,
        hKey,
        lpSubKey,
        Reserved,
        lpClass,
        dwOptions,
        samDesired,
        lpSecurityAttributes,
        phkResult,
        lpdwDisposition,
    ):
        self.__print_opening_unicode(event, "key", lpSubKey)

    def post_CreateFileA(self, event, retval):
        self.__print_success(event, retval)

    def post_CreateFileW(self, event, retval):
        self.__print_success(event, retval)

    def post_RegCreateKeyExA(self, event, retval):
        self.__print_reg_success(event, retval)

    def post_RegCreateKeyExW(self, event, retval):
        self.__print_reg_success(event, retval)

    # Some helper private methods...

    def __print_opening_ansi(self, event, tag, pointer):
        string = event.get_process().peek_string(pointer)
        tid = event.get_tid()
        print("%d: Opening %s: %s" % (tid, tag, string))

    def __print_opening_unicode(self, event, tag, pointer):
        string = event.get_process().peek_string(pointer, fUnicode=True)
        tid = event.get_tid()
        print("%d: Opening %s: %s" % (tid, tag, string))

    def __print_success(self, event, retval):
        tid = event.get_tid()
        if retval:
            print("%d: Success: %x" % (tid, retval))
        else:
            print("%d: Failed!" % tid)

    def __print_reg_success(self, event, retval):
        tid = event.get_tid()
        if retval:
            print("%d: Failed! Error code: %x" % (tid, retval))
        else:
            print("%d: Success!" % tid)


def simple_debugger(argv):
    # Instance a Debug object, passing it the MyEventHandler instance.
    with Debug(MyEventHandler(), bKillOnExit=True) as debug:
        # Start a new process for debugging.
        debug.execv(argv)

        # Wait for the debugee to finish.
        debug.loop()


# When invoked from the command line,
# the first argument is an executable file,
# and the remaining arguments are passed to the newly created process.
if __name__ == "__main__":
    import sys

    simple_debugger(sys.argv[1:])
