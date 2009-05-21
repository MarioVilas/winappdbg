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
Windows application debugging engine for Python.

by Mario Vilas (mvilas at gmail.com)

Project: U{http://sourceforge.net/projects/winappdbg/}

Web:     U{http://winappdbg.sourceforge.net/}

Blog:    U{http://breakingcode.wordpress.com}

@group Instrumentation: System, Process, Thread, Module
@group Debugging: Debug, EventHandler, NoEvent, DebugRegister
@group Crash reporting: Crash, CrashContainer, CrashDump
@group Text input and output: HexInput, HexOutput, HexDump, DebugLog
@group Win32 API wrappers: win32, Handle, ProcessHandle, ThreadHandle, FileHandle
@group Internal use: breakpoint, crash, debug, event, system, textio

@type version: str
@var  version: This WinAppDbg release version.
"""

__revision__ = "$Id$"

# List of all public symbols
__all__ =   [
                # Library version
                'version',

                # from breakpoint import *
                'DebugRegister',

                # from crash import *
                'Crash',
                'CrashContainer',

                # from debug import *
                'Debug',

                # from system import *
                'Module',
                'Thread',
                'Process',
                'System',

                # from debug import *
                'EventHandler',
##                'EventFactory',
                'NoEvent',

                # from textio import *
                'HexDump',
                'HexInput',
                'HexOutput',
                'Table',
                'DebugLog',
                'CrashDump',

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
from system import *
from textio import *
import win32
from win32 import Handle, ProcessHandle, ThreadHandle, FileHandle

# Library version
version = "Version 1.2"
