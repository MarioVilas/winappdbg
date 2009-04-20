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
Debugging module.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging}

@group Instrumentation: System, Process, Thread, Module
@group Debugging: Debug, EventHandler
"""

__all__ =   [
                # the main debugger class
                'Debug',
            ]

import win32
from system import System, Process, Thread, Module, processidparam
from breakpoint import BreakpointContainer
from event import EventHandler, EventDispatcher, EventFactory, ExitProcessEvent

import ctypes
##import traceback

#==============================================================================

class Debug (EventDispatcher, BreakpointContainer):
    """
    The main debugger class.

    @see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging}

    @group Debugging:
        attach, detach, detach_from_all, execv, execl, clear

    @group Debugging loop:
        loop, wait, dispatch, cont, get_debugee_count

    @group Event notifications (private):
        notify_create_process,
        notify_create_thread,
        notify_load_dll,
        notify_exit_process,
        notify_exit_thread,
        notify_unload_dll,
        notify_rip,
        notify_debug_control_c,
        notify_ms_vc_exception

    @type system: L{System}
    @ivar system: A System snapshot that is automatically updated for
        processes being debugged. Processes not being debugged in this snapshot
        may be outdated.
    """

    def __init__(self, eventHandler = None, bKillOnExit = False):
        """
        Debugger object.

        @type  eventHandler: L{EventHandler}
        @param eventHandler:
            (Optional, recommended) Custom event handler object.

        @type  bKillOnExit: bool
        @param bKillOnExit: (Optional) Global kill on exit mode.
            C{True} to kill the process on exit, C{False} to detach.
            Ignored under Windows 2000 and below.

        @note: The L{eventHandler} parameter may be any callable Python object
            (for example a function, or an instance method).
            However you'll probably find it more convenient to use an instance
            of a subclass of L{EventHandler} here.

        @raise WindowsError: Raises an exception on error.
        """
        EventDispatcher.__init__(self, eventHandler)
        BreakpointContainer.__init__(self)

        self.system                         = System()
        self.__bKillOnExit                  = bKillOnExit
        self.__debugeeCount                 = 0
        self.__manuallyStartedProcessesSet  = set()

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

        @see: L{detach}, L{execv}, L{execl}

        @type  dwProcessId: int
        @param dwProcessId: Global ID of a process to attach to.

        @rtype:  L{Process}
        @return: A new Process object.

        @raise WindowsError: Raises an exception on error.
        """
        win32.DebugActiveProcess(dwProcessId)
        self.__manuallyStartedProcessesSet.add(dwProcessId)
        self.__debugeeCount += 1

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

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when detaching.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """
        try:
            self.disable_process_breakpoints(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

        if dwProcessId in self.__manuallyStartedProcessesSet:
            self.__manuallyStartedProcessesSet.remove(dwProcessId)

        try:
            win32.DebugActiveProcessStop(dwProcessId)
            self.__debugeeCount -= 1
        except Exception:
             if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

    def detach_from_all(self, bIgnoreExceptions = False):
        """
        Detaches from all processes currently being debugged.

        @see: L{attach}, L{detach}

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when detaching.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """
        for pid in self.system.get_process_ids():
            try:
                self.detach(pid)
            except Exception, e:
                if not bIgnoreExceptions:
                    raise
##                traceback.print_exc()
##                print

    def execv(self, argv,                                    bConsole = False,
                                                              bFollow = False,
                                                           bSuspended = False):
        """
        Starts a new process for debugging.

        This method uses a list of arguments. To use a command line string
        instead, use L{execl}.

        @see: L{attach}, L{detach}

        @type  argv: list( str... )
        @param argv: List of command line arguments to pass to the debugee.
            The first element must be the debugee executable filename.

        @type  bConsole: bool
        @param bConsole: True to inherit the console of the debugger.

        @type  bFollow: bool
        @param bFollow: C{True} to automatically attach to child processes.

        @type  bSuspended: bool
        @param bSuspended: C{True} to suspend the main thread before any code
            is executed in the debugee.

        @rtype:  L{Process}
        @return: A new Process object.

        @raise WindowsError: Raises an exception on error.
        """
        lpCmdLine = self.system.argv_to_cmdline(argv)
        return self.execl(lpCmdLine,   bConsole = bConsole,
                                        bFollow = bFollow,
                                     bSuspended = bSuspended)

    def execl(self, lpCmdLine,                               bConsole = False,
                                                              bFollow = False,
                                                           bSuspended = False):
        """
        Starts a new process for debugging.

        This method uses a command line string. To use a list of arguments
        instead, use L{execv}.

        @see: L{attach}, L{detach}

        @type  lpCmdLine: str
        @param lpCmdLine: Command line string to execute.
            The first token must be the debugee executable filename.
            Tokens with spaces must be enclosed in double quotes.
            Tokens including double quote characters must be escaped with a
            backslash.

        @type  bConsole: bool
        @param bConsole: C{True} to inherit the console of the debugger.

        @type  bFollow: bool
        @param bFollow: C{True} to automatically attach to child processes.

        @type  bSuspended: bool
        @param bSuspended: C{True} to suspend the main thread before any code
            is executed in the debugee.

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

        self.__manuallyStartedProcessesSet.add(aProcess.get_pid())
        self.__debugeeCount += 1

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
            Use C{INFINITE} or C{None} for no timeout.

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
        Calls the debug event notify callbacks.

        @see: L{cont}, L{loop}, L{wait}

        @type  event: L{Event}
        @param event: Event object returned by L{wait}.

        @raise WindowsError: Raises an exception on error.
        """

        # By default, exceptions are handled by the debugee.
        event.debug.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED

        # Dispatch the debug event.
        return EventDispatcher.dispatch(self, event)

    def cont(self, event):
        """
        Resumes execution after processing a debug event.

        @see: dispatch(), loop(), wait()

        @type  event: L{Event}
        @param event: Event object returned by L{wait}.

        @raise WindowsError: Raises an exception on error.
        """

        # If the process is still alive, flush the instruction cache.
        if not isinstance(event, ExitProcessEvent):
            try:
                event.get_process().flush_instruction_cache()
            except WindowsError:
                pass

        # Continue execution of the debugee.
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
            Use C{INFINITE} or C{None} for no timeout.
            It's NOT recommended to use no timeout, as the user may be unable
            to cancel your program by pressing Control-C.

        @raise WindowsError: Raises an exception on error.
        """
        while self.get_debugee_count() > 0:
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

    def get_debugee_count(self):
        """
        @rtype:  int
        @return: Number of processes being debugged.
        """
        return self.__debugeeCount

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

#------------------------------------------------------------------------------

    def notify_create_process(self, event):
        """
        Notify the creation of a new process.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{ExitProcessEvent}
        @param event: Exit process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwProcessId = event.get_pid()
        if dwProcessId in self.__manuallyStartedProcessesSet:
            self.__manuallyStartedProcessesSet.remove(dwProcessId)
        else:
            self.__debugeeCount += 1
        return self.system.notify_create_process(event)

    def notify_create_thread(self, event):
        """
        Notify the creation of a new thread.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{CreateThreadEvent}
        @param event: Create thread event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        return event.get_process().notify_create_thread(event)

    def notify_load_dll(self, event):
        """
        Notify the load of a new module.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{LoadDLLEvent}
        @param event: Load DLL event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        return event.get_process().notify_load_dll(event)

    def notify_exit_process(self, event):
        """
        Notify the termination of a process.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{ExitProcessEvent}
        @param event: Exit process event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwProcessId = event.get_pid()
        if dwProcessId in self.__manuallyStartedProcessesSet:
            self.__manuallyStartedProcessesSet.remove(dwProcessId)

        self.__debugeeCount -= 1

        bCallHandler = BreakpointContainer.notify_exit_process(self, event)
        bCallHandler = bCallHandler and self.system.notify_exit_process(event)
        return bCallHandler

    def notify_exit_thread(self, event):
        """
        Notify the termination of a thread.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{ExitThreadEvent}
        @param event: Exit thread event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        bCallHandler = BreakpointContainer.notify_exit_thread(self, event)
        bCallHandler = bCallHandler and \
                                  event.get_process().notify_exit_thread(event)
        return bCallHandler

    # TODO
    # Breakpoints should be notified when the DLL they are on is removed.
    def notify_unload_dll(self, event):
        """
        Notify the unload of a module.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{UnloadDLLEvent}
        @param event: Unload DLL event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        return event.get_process().notify_unload_dll(event)

    def notify_rip(self, event):
        """
        Notify of a RIP event.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{RIPEvent}
        @param event: RIP event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        event.debug.detach( event.get_pid() )
        return True

    def notify_debug_control_c(self, event):
        """
        Notify of a Debug Ctrl-C exception.

        @warning: This method is meant to be used internally by the debugger.

        @note: This exception is only raised when a debugger is attached, and
            applications are not supposed to handle it, so we need to handle it
            ourselves or the application may crash.

        @see: U{http://msdn.microsoft.com/en-us/library/aa363082(VS.85).aspx}

        @type  event: L{ExceptionEvent}
        @param event: Debug Ctrl-C exception event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        if event.is_first_chance():
            event.continueStatus = win32.DBG_CONTINUE
        return True

    def notify_ms_vc_exception(self, event):
        """
        Notify of a Microsoft Visual C exception.

        @warning: This method is meant to be used internally by the debugger.

        @note: This allows the debugger to understand the
            Microsoft Visual C thread naming convention.

        @see: U{http://msdn.microsoft.com/en-us/library/xcb2z8hs.aspx}

        @type  event: L{ExceptionEvent}
        @param event: Microsoft Visual C exception event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        dwType = event.get_exception_information(0)
        if dwType == 0x1000:
            pszName     = event.get_exception_information(1)
            dwThreadID  = event.get_exception_information(2)
            dwFlags     = event.get_exception_information(3)

            aProcess = event.get_process()
            szName   = aProcess.peek_string(pszName, fUnicode = False)
            if szName:

                if dwThreadId == -1:
                    dwThreadId = event.get_tid()

                if aProcess.has_thread(dwThreadId):
                    aThread = aProcess.get_thread(dwThreadId)
                else:
                    aThread = Thread(dwThreadId)
                    aProcess._Process__add_thread(aThread)

##                if aThread.get_name() is None:
##                    aThread.set_name(szName)
                aThread.set_name(szName)

        return True
