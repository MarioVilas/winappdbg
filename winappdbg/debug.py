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

# $Id$

"""
Main module.

@see: U{http://code.google.com/p/python-winapp-dbg/wiki/Debugging}

@group Instrumentation: System, Process, Thread, Module
@group Debugging: Debug, EventHandler
"""

__all__ =   [
                # from system.py
                'Module',
                'Thread',
                'Process',
                'System',

                # from event.py
                'EventHandler',

                # the main debugger class
                'Debug',
            ]

import win32
from system import System, Process, Thread, Module, processidparam
from breakpoint import BreakpointContainer
from event import EventHandler, EventFactory

import ctypes
##import traceback

#==============================================================================

class Debug (BreakpointContainer):
    """
    The main debugger class.
    
    @see: U{http://code.google.com/p/python-winapp-dbg/wiki/Debugging}
    
    @type system: L{System}
    @ivar system: A System snapshot that is automatically updated for
        processes being debugged. Processes not being debugged in this snapshot
        may be outdated.
    
    @type debugeeCount: int
    @ivar debugeeCount: Number of processes currently being debugged.
    """

    def __init__(self, eventHandler = None, bKillOnExit = False):
        """
        Debugger object.
        
        @type  eventHandler: L{EventHandler}
        @param eventHandler: (Optional) Custom event handler object.
        
        @type    bKillOnExit: bool
        @keyword bKillOnExit: (Optional) Global kill on exit mode.
            True to kill the process on exit, False to detach.
            Ignored under Windows 2000 and below.
        
        @raise WindowsError: Raises an exception on error.
        """
        super(Debug, self).__init__()

        if eventHandler is None:
            eventHandler = EventHandler()

        self.system             = System()
        self.__eventHandler     = eventHandler
        self.__bKillOnExit      = bKillOnExit
        self.debugeeCount       = 0

##        self.system.request_debug_privileges(bIgnoreExceptions = True)
        self.system.request_debug_privileges()

    # Detach from all processes on exit.
    def __del__(self):
        try:
            if not self.__bKillOnExit:
                self.detach_from_all(bIgnoreExceptions = True)
        except Exception, e:
            pass
##            traceback.print_exc()
##            print

#------------------------------------------------------------------------------

    @processidparam
    def attach(self, dwProcessId):
        """
        Attaches to an existing process for debugging.
        
        @see: L{start}, L{detach}
        
        @type  dwProcessId: int
        @param dwProcessId: Global ID of a process to attach to.
        
        @rtype:  L{Process}
        @return: A new Process object.
        
        @raise WindowsError: Raises an exception on error.
        """
        DebugActiveProcess(dwProcessId)
        self.debugeeCount += 1

        # We can only set the kill on exit mode after having
        # established at least one debugging connection.
        self.system.set_kill_on_exit_mode(self.__bKillOnExit)

        # The process has to be registered with the debugger,
        # otherwise the list of processes may be empty, and the
        # debugger loop will quit too soon. When the create process
        # event arrives, the process handle is replaced.
        if not self.system.has_process(dwProcessId):
            aProcess = Process(dwProcessId)
            self.system._ProcessContainer__add_process(aProcess)
        else:
            aProcess = self.system.get_process(dwProcessId)

        # XXX
        # Scan the process threads and loaded modules.
        # This is prefered because the thread and library events do not
        # properly give some information, like the filename for each module.
        aProcess.scan_threads()
        aProcess.scan_modules()

        return aProcess

    @processidparam
    def detach(self, dwProcessId, bIgnoreExceptions = False):
        """
        Detaches from a process currently being debugged.
        
        @see: L{attach}, L{detach_from_all}
        
        @type  dwProcessId: int
        @param dwProcessId: Global ID of a process to detach from.
        
        @type    bIgnoreExceptions: bool
        @keyword bIgnoreExceptions: True to ignore any exceptions that may be
            raised when detaching.
        
        @raise WindowsError: Raises an exception on error, unless
            bIgnoreExceptions is True.
        """
        try:
            self.disable_process_breakpoints(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print
        try:
            DebugActiveProcessStop(dwProcessId)
            self.debugeeCount -= 1
        except Exception:
             if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

    def detach_from_all(self, bIgnoreExceptions = False):
        """
        Detaches from all processes currently being debugged.
        
        @see: L{attach}, L{detach}
        
        @type    bIgnoreExceptions: bool
        @keyword bIgnoreExceptions: True to ignore any exceptions that may be
            raised when detaching.
        
        @raise WindowsError: Raises an exception on error, unless
            bIgnoreExceptions is True.
        """
        for pid in self.system.get_process_ids():
            try:
                self.detach(pid)
            except Exception, e:
                if not bIgnoreExceptions:
                    raise
##                traceback.print_exc()
##                print

    def start(self, lpCmdLine,                               bConsole = False,
                                                              bFollow = False,
                                                           bSuspended = False):
        """
        Starts a new process for debugging.
        
        @see: L{attach}, L{detach}
        
        @type  lpCmdLine: str
        @param lpCmdLine: Command line string to execute.
            The first token must be the debugee executable filename.
            Tokens with spaces must be enclosed in double quotes.
            Tokens including double quote characters must be escaped with a
            backslash.
        
        @type    bConsole: bool
        @keyword bConsole: True to inherit the console of the debugger.
        
        @type    bFollow: bool
        @keyword bFollow: True to automatically attach to child processes.
        
        @type    bSuspended: bool
        @keyword bSuspended: True to suspend the main thread before any code is
            executed in the debugee.
        
        @rtype:  L{Process}
        @return: A new Process object.
        
        @raise WindowsError: Raises an exception on error.
        """
        aProcess = self.system.start_process(lpCmdLine,
            bConsole    = bConsole,
            bDebug      = True,
            bFollow     = bFollow,
            bSuspended  = bSuspended
        )

        self.debugeeCount += 1

        # We can only set the kill on exit mode after having
        # established at least one debugging connection.
        self.system.set_kill_on_exit_mode(self.__bKillOnExit)

        return aProcess

#------------------------------------------------------------------------------

    def wait(self, dwMilliseconds = None):
        """
        Waits for the next debug event and returns an L{Event} object.
        
        @see: L{cont}, L{dispatch}, L{loop}
        
        @type  dwMilliseconds: int
        @param dwMilliseconds: Timeout in milliseconds.
            Use INFINITE or None for no timeout.
        
        @rtype:  L{Event}
        @return: An event that occured in one of the debugees.
        
        @raise WindowsError: Raises an exception on error.
        """
        if dwMilliseconds is None:
            dwMilliseconds = win32.INFINITE
        raw                  = win32.DEBUG_EVENT()
        raw.dwDebugEventCode = 0
        raw.dwProcessId      = 0
        raw.dwThreadId       = 0
        win32.WaitForDebugEvent(raw, dwMilliseconds)
        return EventFactory.get(self, raw)

    def dispatch(self, event):
        """
        Calls the debug event handler functions.
        
        @see: L{cont}, L{loop}, L{wait}
        
        @type  event: L{Event}
        @param event: Event object returned by wait().
        
        @raise WindowsError: Raises an exception on error.
        """
        self.__eventHandler(event)

    def cont(self, event):
        """
        Resumes execution after processing a debug event.
        
        @see: dispatch(), loop(), wait()
        
        @type  event: L{Event}
        @param event: Event object returned by wait().
        
        @raise WindowsError: Raises an exception on error.
        """
        event.get_process().flush_instruction_cache()
        dwProcessId      = event.get_pid()
        dwThreadId       = event.get_tid()
        dwContinueStatus = event.continueStatus
        win32.ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)

    def loop(self, dwMilliseconds = 1000):
        """
        Main debugging loop.
        
        @see: L{cont}, L{dispatch}, L{wait}
            
            U{http://msdn.microsoft.com/en-us/library/ms681675(VS.85).aspx}
        
        @type  dwMilliseconds: int
        @param dwMilliseconds: Timeout for each wait, in milliseconds.
            Use INFINITE or None for no timeout.
            It's NOT recommended to use no timeout, as the user may be unable
            to cancel your program by pressing Control-C.
        
        @raise WindowsError: Raises an exception on error.
        """
        while self.debugeeCount > 0:
            try:
                event = self.wait(dwMilliseconds)
            except WindowsError, e:
                if e.winerror == win32.ERROR_SEM_TIMEOUT:
                    continue
                raise
            try:
                self.dispatch(event)
            except Exception:
                raise
##                pass
##                traceback.print_exc()
##                print
            self.cont(event)

##    def __bool__(self):
##        return self.debugeeCount > 0

#------------------------------------------------------------------------------

    def clear(self):
        """
        Detach from all processes and clean up internal structures.
        
        @see: L{System}
        
        @raise WindowsError: Raises an exception on error.
        """
        self.erase_all_breakpoints()
        self.detach_from_all()
        self.system.clear()
