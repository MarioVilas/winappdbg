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
Debugging module.

@see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging}

@group Debugging:
    Debug
"""

__revision__ = "$Id$"

__all__ =   [
                # the main debugger class
                'Debug',
            ]

import win32
from system import System, Process, Thread, Module
from breakpoint import BreakpointContainer, CodeBreakpoint
from event import EventHandler, EventDispatcher, EventFactory, ExitProcessEvent

import sys
import ctypes
##import traceback

#==============================================================================

# TODO
# * Add memory read and write operations, similar to those in the Process
#   class, but hiding the presence of the code breakpoints.
# * Add a method to get the memory map of a process, but hiding the presence
#   of the page breakpoints.
# * Maybe the previous two features should be implemented at the Process class
#   instead, but how to communicate with the Debug object without creating
#   circular references? Perhaps the "overrides" could be set using private
#   members (so users won't see them), but then there's the problem of the
#   users being able to access the snapshot (i.e. clear it), which is why it's
#   not such a great idea to use the snapshot to store data that really belongs
#   to the Debug class.

class Debug (EventDispatcher, BreakpointContainer):
    """
    The main debugger class.

    @see: U{http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Debugging}

    @group Debugging:
        attach, detach, detach_from_all, execv, execl, clear,
        get_debugee_count, get_debugee_pids,
        is_debugee, is_debugee_attached, is_debugee_started

    @group Debugging loop:
        loop, next, wait, dispatch, cont, stop

    @group Event notifications (private):
        notify_create_process,
        notify_create_thread,
        notify_load_dll,
        notify_unload_dll,
        notify_rip,
        notify_debug_control_c,
        notify_ms_vc_exception

    @type system: L{System}
    @ivar system: A System snapshot that is automatically updated for
        processes being debugged. Processes not being debugged in this snapshot
        may be outdated.
    """

    def __init__(self, eventHandler = None,              bKillOnExit = False,
                                                        bHostileCode = False):
        """
        Debugger object.

        @type  eventHandler: L{EventHandler}
        @param eventHandler:
            (Optional, recommended) Custom event handler object.

        @type  bKillOnExit: bool
        @param bKillOnExit: (Optional) Global kill on exit mode.
            C{True} to kill the process on exit, C{False} to detach.
            Ignored under Windows 2000 and below.

        @type  bHostileCode: bool
        @param bHostileCode: (Optional) Hostile code mode.
            Set to C{True} to take some basic precautions against anti-debug
            tricks. Disabled by default.

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
        self.__bHostileCode                 = bHostileCode
        self.__attachedDebugees             = set()
        self.__startedDebugees              = set()

##        self.system.request_debug_privileges(bIgnoreExceptions = True)
        self.system.request_debug_privileges()

##    # It's not hard to create circular references,
##    # and if we have a destructor, we can end up leaking everything.
##    # It's best to code the debugging loop properly to always
##    # stop the debugger before going out of scope.
##    def __del__(self):
##        try:
##            self.stop()
##        except Exception, e:
##            pass
####            traceback.print_exc()
####            print

    def __len__(self):
        """
        @rtype:  int
        @return: Number of processes being debugged.
        """
        return self.get_debugee_count()

#------------------------------------------------------------------------------

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
        self.__attachedDebugees.add(dwProcessId)

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

        # Disable all breakpoints in the process.
        # XXX maybe they should be erased?
        try:
            self.disable_process_breakpoints(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

        # Stop tracing all threads in the process.
        try:
            self.stop_tracing_process(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

        # The process is no longer a debugee.
        try:
            if dwProcessId in self.__attachedDebugees:
                self.__attachedDebugees.remove(dwProcessId)
            if dwProcessId in self.__startedDebugees:
                self.__startedDebugees.remove(dwProcessId)
        except Exception:
            if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

        # One might think of removing the process from the snapshot.
        # But the process is not dead, and the user may want to do
        # something with it after detaching.
##        try:
##            self.system._Process_Container__del_process(dwProcessId)
##        except Exception:
##            if not bIgnoreExceptions:
##                raise

        # Detach from the process.
        try:
            win32.DebugActiveProcessStop(dwProcessId)
        except Exception:
             if not bIgnoreExceptions:
                raise
##            traceback.print_exc()
##            print

    def detach_from_all(self, bIgnoreExceptions = False):
        """
        Detaches from all processes currently being debugged.

        @note: To better handle last debugging event, call L{stop} instead.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when detaching.

        @raise WindowsError: Raises an exception on error, unless
            C{bIgnoreExceptions} is C{True}.
        """
        for pid in self.get_debugee_pids():
            self.detach(pid, bIgnoreExceptions = bIgnoreExceptions)

    def execv(self, argv,                                    bConsole = False,
                                                              bFollow = False,
                                                           bSuspended = False,
                                                      bInheritHandles = False,
                                                    dwParentProcessId = None):
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
            Defaults to C{False}.

        @type  bFollow: bool
        @param bFollow: C{True} to automatically attach to child processes.
            Defaults to C{False}.

        @type  bSuspended: bool
        @param bSuspended: C{True} to suspend the main thread before any code
            is executed in the debugee. Defaults to C{False}.

        @type  bInheritHandles: bool
        @param bInheritHandles: C{True} if the new process should inherit it's
            parent process' handles. Defaults to C{False}.

        @type  dwParentProcessId: int or None
        @param dwParentProcessId: C{None} if the debugger process should be the
            parent process (default), or a process ID to forcefully set as the
            debugee's parent (only available for Windows Vista and above).

        @rtype:  L{Process}
        @return: A new Process object.

        @raise WindowsError: Raises an exception on error.
        """
        lpCmdLine = self.system.argv_to_cmdline(argv)
        return self.execl(lpCmdLine,   bConsole = bConsole,
                                        bFollow = bFollow,
                                     bSuspended = bSuspended,
                                bInheritHandles = bInheritHandles,
                              dwParentProcessId = dwParentProcessId)

    def execl(self, lpCmdLine,                               bConsole = False,
                                                              bFollow = False,
                                                           bSuspended = False,
                                                      bInheritHandles = False,
                                                    dwParentProcessId = None):
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
            Defaults to C{False}.

        @type  bFollow: bool
        @param bFollow: C{True} to automatically attach to child processes.
            Defaults to C{False}.

        @type  bSuspended: bool
        @param bSuspended: C{True} to suspend the main thread before any code
            is executed in the debugee. Defaults to C{False}.

        @type  bInheritHandles: bool
        @param bInheritHandles: C{True} if the new process should inherit it's
            parent process' handles. Defaults to C{False}.

        @type  dwParentProcessId: int or None
        @param dwParentProcessId: C{None} if the debugger process should be the
            parent process (default), or a process ID to forcefully set as the
            debugee's parent (only available for Windows Vista and above).

        @rtype:  L{Process}
        @return: A new Process object.

        @raise WindowsError: Raises an exception on error.
        """
        aProcess = self.system.start_process(lpCmdLine,
            bConsole          = bConsole,
            bDebug            = True,
            bFollow           = bFollow,
            bSuspended        = bSuspended,
            bInheritHandles   = bInheritHandles,
            dwParentProcessId = dwParentProcessId,
        )

        self.__startedDebugees.add( aProcess.get_pid() )

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
        @param dwMilliseconds: (Optional) Timeout in milliseconds.
            Use C{INFINITE} or C{None} for no timeout.

        @rtype:  L{Event}
        @return: An event that occured in one of the debugees.

        @raise WindowsError: Raises an exception on error.
        """

        # Return the next debug event.
        raw     = win32.WaitForDebugEvent(dwMilliseconds)
        event   = EventFactory.get(self, raw)
        return event

    def dispatch(self, event):
        """
        Calls the debug event notify callbacks.

        @see: L{cont}, L{loop}, L{wait}

        @type  event: L{Event}
        @param event: Event object returned by L{wait}.

        @raise WindowsError: Raises an exception on error.
        """

        # Ignore dummy events.
        if not event:
            return

        # By default, exceptions are handled by the debugee.
        if event.get_event_code() == win32.EXCEPTION_DEBUG_EVENT:
            event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
        else:
            # Other events need this continue code.
            # Sometimes other codes can be used and are ignored, sometimes not.
            # For example, when using the DBG_EXCEPTION_NOT_HANDLED code,
            # debug strings are sent twice (!)
            event.continueStatus = win32.DBG_CONTINUE

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

        # Ignore dummy events.
        if not event:
            return

        # Get the event continue status information.
        dwProcessId      = event.get_pid()
        dwThreadId       = event.get_tid()
        dwContinueStatus = event.continueStatus

        # Try to flush the instruction cache.
        try:
            if self.system.has_process(dwProcessId):
                aProcess = self.system.get_process(dwProcessId)
            else:
                aProcess = Process(dwProcessId)
            aProcess.flush_instruction_cache()
        except WindowsError:
            pass

        # Continue execution of the debugee.
        win32.ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus)

    def stop(self, event = None, bIgnoreExceptions = True):
        """
        Stops debugging all processes.

        If C{bKillOnExit} was set to C{True} when instancing the C{Debug}
        object, all debugees are terminated. Otherwise, the debugger detaches
        from all debugees.

        @note: This method is better than L{detach_from_all} because it can
            gracefully handle the last debugging event before detaching.

        @type  event: L{Event}
        @param event: (Optional) Event object returned by L{wait}.
            By passing this parameter, the last debugging event may be
            continued gracefully.

        @type  bIgnoreExceptions: bool
        @param bIgnoreExceptions: C{True} to ignore any exceptions that may be
            raised when detaching.
        """
        # All these try / except / finally blocks may be masking some errors,
        # but this way we get a better cleanup. Like that battery-powered
        # rabbit, it just keeps going, and going, and going.
        try:
            if self.__bKillOnExit:
                for pid in self.get_debugee_pids():
                    try:
                        self.system.get_process(pid).kill()
                    except Exception:
                        if not bIgnoreExceptions:
                            raise
            try:
                if event:
                    try:
                        try:
                            pid = event.get_pid()
                            self.disable_process_breakpoints(pid)
                        finally:
                            self.cont(event)
                    except Exception:
                        if not bIgnoreExceptions:
                            raise
            finally:
                self.detach_from_all(bIgnoreExceptions)
        except Exception:
            if not bIgnoreExceptions:
                raise

    def next(self):
        """
        Handles the next debug event.

        @see: L{cont}, L{dispatch}, L{wait}, L{stop}

        @rtype:  L{Event}
        @return: Handled debug event.

        @raise WindowsError: Raises an exception on error.

            If the wait operation causes an error, debugging is stopped
            (meaning all debugees are either killed or detached from).

            If the event dispatching causes an error, the event is still
            continued before returning. This may happen, for example, if the
            event handler raises an exception nobody catches.
        """
        try:
            event = self.wait()
        except Exception:
            self.stop()
        try:
            self.dispatch(event)
        finally:
            self.cont(event)
        return event

    def loop(self):
        """
        Simple debugging loop.

        This debugging loop is meant to be useful for most simple scripts.
        It iterates as long as there is at least one debugee, or an exception
        is raised. Multiple calls are allowed.

        This is a trivial example script::

            import sys
            debug = Debug()
            debug.execv( sys.argv [ 1 : ] )
            try:
                debug.loop()
            finally:
                debug.stop()

        @see: L{next}, L{stop}

            U{http://msdn.microsoft.com/en-us/library/ms681675(VS.85).aspx}

        @raise WindowsError: Raises an exception on error.

            If the wait operation causes an error, debugging is stopped
            (meaning all debugees are either killed or detached from).

            If the event dispatching causes an error, the event is still
            continued before returning. This may happen, for example, if the
            event handler raises an exception nobody catches.
        """
        while self.get_debugee_count() > 0:
            self.next()

    def get_debugee_count(self):
        """
        @rtype:  int
        @return: Number of processes being debugged.
        """
        return len(self.__attachedDebugees) + len(self.__startedDebugees)

    def get_debugee_pids(self):
        """
        @rtype:  list( int... )
        @return: Global IDs of processes being debugged.
        """
        return list(self.__attachedDebugees) + list(self.__startedDebugees)

    def is_debugee(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.

        @rtype:  bool
        @return: C{True} if the given process is being debugged
            by this L{Debug} instance.
        """
        return self.is_debugee_attached(dwProcessId) or \
               self.is_debugee_started(dwProcessId)

    def is_debugee_started(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.

        @rtype:  bool
        @return: C{True} if the given process was started for debugging by this
            L{Debug} instance.
        """
        return dwProcessId in self.__startedDebugees

    def is_debugee_attached(self, dwProcessId):
        """
        @type  dwProcessId: int
        @param dwProcessId: Process global ID.

        @rtype:  bool
        @return: C{True} if the given process is attached to this
            L{Debug} instance.
        """
        return dwProcessId in self.__attachedDebugees

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
        if dwProcessId not in self.__attachedDebugees:
            if dwProcessId not in self.__startedDebugees:
                self.__startedDebugees.add(dwProcessId)

        retval = self.system.notify_create_process(event)

        # Defeat isDebuggerPresent by patching PEB->BeingDebugged.
        # When we do this, some debugging APIs cease to work as expected.
        # For example, the system breakpoint isn't hit when we attach.
        # For that reason we need to define a code breakpoint at the
        # code location where a new thread is spawned by the debugging
        # APIs, ntdll!DbgUiRemoteBreakin.
        if self.__bHostileCode:
            aProcess = self.system.get_process(dwProcessId)
            try:
                pbi = win32.NtQueryInformationProcess(aProcess.get_handle(),
                                                 win32.ProcessBasicInformation)
                ptr = pbi.PebBaseAddress + 2
                if aProcess.peek(ptr, 1) == '\x01':
                    aProcess.poke(ptr, '\x00')
            except WindowsError:
                pass

        return retval

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

        # Get the process where the DLL was loaded.
        aProcess = event.get_process()

        # Pass the event to the process.
        retval = aProcess.notify_load_dll(event)

        # Anti-anti-debugging tricks on ntdll.dll.
        if self.__bHostileCode:
            aModule = event.get_module()
            if aModule.match_name('ntdll.dll'):

##                # Check the int3 instruction where
##                # the system breakpoint should be.
##                # If missing, restore it. This defeats
##                # a simple anti-debugging trick.
####                address = aModule.resolve('DbgBreakPoint')
####                address = aModule.resolve('DbgUserBreakPoint')
##                address = aProcess.get_system_breakpoint()
##                if address is not None:
##                    aProcess.poke(address, CodeBreakpoint.int3)
##                address = aProcess.get_user_breakpoint()
##                if address is not None:
##                    aProcess.poke(address, CodeBreakpoint.int3)

                # Since we've overwritten the PEB to hide
                # ourselves, we no longer have the system
                # breakpoint when attaching to the process.
                # Set a breakpoint at ntdll!DbgUiRemoteBreakin
                # instead (that's where the debug API spawns
                # it's auxiliary threads). This also defeats
                # a simple anti-debugging trick: the hostile
                # process could have overwritten the int3
                # instruction at the system breakpoint.
                DbgUiRemoteBreakin = 'ntdll!DbgUiRemoteBreakin'
                DbgUiRemoteBreakin = aProcess.resolve_label(DbgUiRemoteBreakin)
                self.break_at(aProcess.get_pid(), DbgUiRemoteBreakin)

        return retval

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
        if dwProcessId in self.__attachedDebugees:
            self.__attachedDebugees.remove(dwProcessId)
        if dwProcessId in self.__startedDebugees:
            self.__startedDebugees.remove(dwProcessId)

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

    def notify_unload_dll(self, event):
        """
        Notify the unload of a module.

        @warning: This method is meant to be used internally by the debugger.

        @type  event: L{UnloadDLLEvent}
        @param event: Unload DLL event.

        @rtype:  bool
        @return: C{True} to call the user-defined handle, C{False} otherwise.
        """
        bCallHandler = BreakpointContainer.notify_unload_dll(self, event)
        bCallHandler = bCallHandler and \
                                event.get_process().notify_unload_dll(event)

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

##    def notify_breakpoint(self, event):
##        """
##        Notify the debugger of a breakpoint exception event.
##
##        @type  event: L{ExceptionEvent}
##        @param event: Breakpoint exception event.
##        """
##        # Defeat isDebuggerPresent by patching PEB->BeingDebugged.
##        if self.__bHostileCode:
##            address = event.get_exception_address()
##            if event.get_process().get_system_breakpoint() == address:
##                aProcess = self.system.get_process(dwProcessId)
##                try:
##                    pbi = win32.NtQueryInformationProcess(aProcess.get_handle(),
##                                                     win32.ProcessBasicInformation)
##                    ptr = pbi.PebBaseAddress + 2
##                    if aProcess.peek(ptr, 1) == '\x01':
##                        aProcess.poke(ptr, '\x00')
##                except WindowsError:
##                    pass
##        return BreakpointContainer.notify_breakpoint(self, event)

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
            event.continueStatus = win32.DBG_EXCEPTION_HANDLED
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
            dwThreadId  = event.get_exception_information(2)
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
                    aProcess._ThreadContainer__add_thread(aThread)

##                if aThread.get_name() is None:
##                    aThread.set_name(szName)
                aThread.set_name(szName)

        return True
