#!~/.wine/drive_c/Python25/python.exe
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
Windows application debugging engine for Python.

by Mario Vilas (mvilas at gmail.com)

Project: U{http://sourceforge.net/projects/winappdbg/}

Web:     U{http://winappdbg.sourceforge.net/}

Blog:    U{http://breakingcode.wordpress.com}

@group Debugging:
    Debug, EventHandler, DebugLog, ConsoleDebugger

@group Instrumentation:
    System, Process, Thread, Module, Window

@group Crash reporting:
    Crash, CrashDump, CrashContainer, CrashTable, CrashTableMSSQL,
    VolatileCrashContainer, DummyCrashContainer

@group Debug events:
    Event,
    NoEvent,
    CreateProcessEvent,
    CreateThreadEvent,
    ExitProcessEvent,
    ExitThreadEvent,
    LoadDLLEvent,
    UnloadDLLEvent,
    OutputDebugStringEvent,
    RIPEvent,
    ExceptionEvent

@group Win32 API wrappers:
    win32, Handle, ProcessHandle, ThreadHandle, FileHandle

@group Miscellaneous:
    HexInput, HexOutput, HexDump, Table, Logger,
    PathOperations,
    MemoryAddresses,
    CustomAddressIterator,
    DataAddressIterator,
    ImageAddressIterator,
    MappedAddressIterator,
    ExecutableAddressIterator,
    ReadableAddressIterator,
    WriteableAddressIterator,
    ExecutableAndWriteableAddressIterator,
    DebugRegister,
    Regenerator

@type version: str
@var  version: This WinAppDbg release version.
"""

__revision__ = "$Id$"

# List of all public symbols
__all__ =   [
                # Library version
                'version',
                'version_number',

                # from breakpoint import *
##                'Breakpoint',
##                'CodeBreakpoint',
##                'PageBreakpoint',
##                'HardwareBreakpoint',
##                'Hook',
##                'ApiHook',
##                'BufferWatch',
                'BreakpointWarning',
                'BreakpointCallbackWarning',

                # from crash import *
                'Crash',
                'CrashDictionary',
                'CrashContainer',
                'CrashTable',
                'CrashTableMSSQL',
                'VolatileCrashContainer',
                'DummyCrashContainer',

                # from interactive import *
                'ConsoleDebugger',

                # from debug import *
                'Debug',
                'MixedBitsWarning',

                # from module import *
                'Module',

                # from thread import *
                'Thread',

                # from window import *
                'Window',

                # from process import *
                'Process',

                # from system import *
                'System',

                # from registry import *
                'Registry',

                # from event import *
                'EventHandler',
                'EventSift',
##                'EventFactory',
##                'EventDispatcher',
                'Event',
##                'NoEvent',
                'CreateProcessEvent',
                'CreateThreadEvent',
                'ExitProcessEvent',
                'ExitThreadEvent',
                'LoadDLLEvent',
                'UnloadDLLEvent',
                'OutputDebugStringEvent',
                'RIPEvent',
                'ExceptionEvent',

                # from textio import *
                'HexDump',
                'HexInput',
                'HexOutput',
                'Table',
                'CrashDump',
                'DebugLog',
                'Logger',

                # from util import *
                'PathOperations',
                'MemoryAddresses',
                'CustomAddressIterator',
                'DataAddressIterator',
                'ImageAddressIterator',
                'MappedAddressIterator',
                'ExecutableAddressIterator',
                'ReadableAddressIterator',
                'WriteableAddressIterator',
                'ExecutableAndWriteableAddressIterator',
                'DebugRegister',

                # import win32
                'win32',

                # from win32 import Handle, ProcessHandle, ThreadHandle, FileHandle
                'Handle',
                'ProcessHandle',
                'ThreadHandle',
                'FileHandle',
            ]

# Import all public symbols
from breakpoint import *
from crash import *
from debug import *
from event import *
from interactive import *
from module import *
from process import *
from registry import *
from textio import *
from thread import *
from util import *
from system import *
from window import *

import win32
from win32 import Handle, ProcessHandle, ThreadHandle, FileHandle

try:
    from sql import *
    __all__.append('CrashDAO')
except ImportError:
    import warnings
    warnings.warn("No SQL database support present (missing dependencies?)",
                  ImportWarning)

# Library version
version_number = 1.5
version = "Version %s" % version_number
