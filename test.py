#!/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2018, Mario Vilas
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

"WinAppDbg test suite"

import os
import ntpath
import warnings

def test(title, fn):
    title = "Testing %s... " % title
    print title,
    try:
        fn()
        print "\tOK"
        return True
    except Exception, e:
        print "\tFAIL: %s" % str(e)
        return False

def test_module_load():
    import winappdbg

def test_disassembler_load():
    from winappdbg import Disassembler, win32
    Disassembler(win32.ARCH_I386)
    Disassembler(win32.ARCH_AMD64)

def test_sqlalchemy_load():
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from winappdbg import sql

def test_windbg_version():
    from winappdbg import System, win32
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        dbghelp = System.load_dbghelp()
    if dbghelp is None:
        raise RuntimeError("WinDbg not found")
    pathname = win32.GetModuleFileNameEx(-1, dbghelp._handle)
    sysroot = os.getenv("SystemRoot")
    if not sysroot:
        sysroot = os.getenv("SYSTEMROOT")
    system = ntpath.join(sysroot, "System32")
    syswow = ntpath.join(sysroot, "SysWoW64")
    if (pathname.lower().startswith(system.lower()) or
        pathname.lower().startswith(syswow.lower())
    ):
        raise RuntimeError("Microsoft SDK not found")

if __name__ == '__main__':
    if test("module load", test_module_load):
        test("disassembler", test_disassembler_load)
        test("SQL support", test_sqlalchemy_load)
        test("WinDbg integration", test_windbg_version)
