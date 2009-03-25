#!~/.wine/drive_c/Python25/python.exe

# Crash dumper
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

__all__ =   [
                'LoggingEventHandler',
            ]

from winappdbg import *

import os
import re
import sys
import time
import optparse
import traceback

#==============================================================================

class LoggingEventHandler(EventHandler):
    (
    'Event handler that logs all events to standard output.'
    ' It also remembers crashes, bugs or otherwise interesting events.'
    )

    # API hooks to track down heap operations.
    apiHooks = {
        
        'kernel32.dll' : [

            # Function name     Parameter count
            ('HeapAlloc',       3),
            ('HeapReAlloc',     4),
            ('HeapFree',        3),
            ('LocalAlloc',      2),
            ('LocalReAlloc',    3),
            ('LocalFree',       1),
            ('GlobalAlloc',     2),
            ('GlobalReAlloc',   3),
            ('GlobalFree',      1),
        ],
        
        'msvcrt.dll' : [

            # Function name     Parameter count
            ('malloc',          1),
            ('free',            1),
        ],
        
    }

    # Regular expression to extract 8 digit hexadecimal numbers.
    re_hexa = re.compile('[0-9A-F]' * 8, re.I)

    def __init__(self, options):

        # Create the crash container.
        self.knownCrashes = CrashContainer()

        # Create the heap tracker.
        self.processHeapLocation = dict()           # pid -> ptr -> pc

        # Copy the user-defined options.
        self.verbose  = options.verbose
        self.break_at = options.break_at
        self.stalk_at = options.stalk_at

        if not self.break_at:
            self.break_at = ( list(), list() )
        if not self.stalk_at:
            self.stalk_at = ( list(), list() )

        # When not tracking down heap operations, remove the API hooks.
        if not options.heap:
            self.apiHooks = dict()

        # Call the base class constructor.
        super(LoggingEventHandler, self).__init__()

    def __log(self, event, text):
        if self.verbose:
            print DebugLog.log_event(event, text)

#-- Events --------------------------------------------------------------------

    # Handle all events not handled by the following class methods.
    def event(self, event):

        # Generate a crash object.
        crash = Crash(event)

        # Log the event to standard output.
        if self.verbose:
            if crash not in self.knownCrashes:
                msg = crash.fullReport()
            else:
                msg = crash.briefReport()
            self.__log(event, msg)

        # Add the crash object to the container.
        self.knownCrashes.add(crash)

    # Handle the create process events.
    def create_process(self, event):
        try:

            # Set user-defined breakpoints for this process.
            pid = event.get_pid()
            event.debug.break_at_address_list(pid, self.break_at[0])
            event.debug.stalk_at_address_list(pid, self.stalk_at[0])

        finally:

            # Log the event to standard output.
            if self.verbose:
                lpStartAddress = event.get_start_address()
                szFilename = event.get_filename()
                if not szFilename:
                    szFilename = Module.unknown
                if lpStartAddress:
                    msg = "Process %s started, entry point at 0x%.8x"
                    msg = msg % (szFilename, lpStartAddress)
                else:
                    msg = "Process %s started" % szFilename
                self.__log(event, msg)

    # Handle the create thread events.
    def create_thread(self, event):

        # Log the event to standard output.
        if self.verbose:
            lpStartAddress = event.get_start_address()
            msg = "Thread started, entry point at 0x%.8x" % lpStartAddress
            self.__log(event, msg)

    # Handle the load dll events.
    def load_dll(self, event):
        dwProcessId = event.get_pid()
        aModule     = event.get_module()
        lpBaseOfDll = aModule.get_base()
        fileName    = aModule.get_filename()
        baseName    = fileName[ fileName.rfind('\\') + 1: ]     # XXX
        try:

            # Set user-defined breakpoints for this process.
            event.debug.break_at_symbol_list(dwProcessId, self.break_at[1],
                                               only_for_this_module = baseName)
            event.debug.stalk_at_symbol_list(dwProcessId, self.stalk_at[1],
                                               only_for_this_module = baseName)

        finally:

            # Log the event to standard output.
            if self.verbose:
                self.__log(event, "Loaded %s at 0x%.8x" % (fileName, lpBaseOfDll))

    # Handle the exit process events.
    def exit_process(self, event):

        # Log the event to standard output.
        if self.verbose:
            dwExitCode = event.get_exit_code()
            self.__log(event, "Process terminated, exit code 0x%x" % dwExitCode)

    # Handle the exit thread events.
    def exit_thread(self, event):

        # Log the event to standard output.
        if self.verbose:
            dwExitCode = event.get_exit_code()
            self.__log(event, "Thread terminated, exit code 0x%x" % dwExitCode)

    # Handle the unload dll events.
    def unload_dll(self, event):

        # Log the event to standard output.
        if self.verbose:
            aModule     = event.get_module()
            lpBaseOfDll = aModule.get_base()
            fileName    = aModule.get_filename()
            self.__log(event, "Unloaded %s at %.8x" % (fileName, lpBaseOfDll))

    # Handle the debug output string events.
    def output_string(self, event):

        # Generate a crash object.
        crash = Crash(event)

##        # Find any potential heap block addresses in the debug string.
##        pid = event.get_pid()
##        if self.processHeapLocation.has_key(pid):
##            known_block_dict = self.processHeapLocation[pid]
##            if known_block_dict:
##                address_list = self.re_hexa.findall(event.get_debug_string())
##                for address in address_list:
##                    address = long( '0x%s' % address, 0x10 )
##
##                    # XXX
##                    # detect if address is within block
##
##                        pc  = known_block_dict[address]
##                        msg = "Heap block %.08x allocated from %.08x"
##                        msg = msg % (address, pc)
##                        crash.addNote(msg)

        # Add the crash object to the container.
        self.knownCrashes.add(crash)

        # Log the event to standard output.
        self.__log(event, crash.briefReport())

    # Handle the RIP events.
    def rip(self, event):

        # Generate a crash object.
        crash = Crash(event)

        # Add the crash object to the container.
        self.knownCrashes.add(crash)

        # Log the event to standard output.
        if self.verbose:
            errorCode = event.get_rip_error()
            errorType = event.get_rip_type()
            if errorType == 0:
                msg = "RIP error at thread %d, code %d"
            elif errorType == SLE_ERROR:
                msg = "RIP fatal error at thread %d, code %d"
            elif errorType == SLE_MINORERROR:
                msg = "RIP minor error at thread %d, code %d"
            elif errorType == SLE_WARNING:
                msg = "RIP warning at thread %d, code %d"
            else:
                msg = "RIP error type %d, code %%d" % errorType
            self.__log(event, msg % errorCode)

#-- Exceptions ----------------------------------------------------------------

    # Handle single step events.
    def single_step(self, event):

        # Continue without setting the trap flag.
        event.continueStatus = win32.DBG_CONTINUE

        # Log the event to standard output.
        if self.verbose:
            address = event.get_exception_address()
            self.__log(event, "Single step event at 0x%.8x" % address)

    # Handle breakpoints events.
    def breakpoint(self, event):

        # Step over breakpoints.
        # This includes both user-defined and hardcoded in the binary.
        event.continueStatus = win32.DBG_CONTINUE

        # Log the event to standard output.
        if self.verbose:
            aProcess = event.get_process()
            address  = event.get_exception_address()
            if address == aProcess.get_system_breakpoint():
                msg = "System breakpoint hit"
            else:
                aModule = aProcess.get_module_from_address(address)
                if aModule is not None:
                    modFileName = aModule.fileName
                    if modFileName == Module.unknown:
                        lpBaseOfDll = aModule.lpBaseOfDll
                        modFileName = '<unknown: %.8x>' % lpBaseOfDll
                    msg = "Breakpoint event at 0x%.8x (%s)" % (address, modFileName)
                else:
                    msg = "Breakpoint event at 0x%.8x" % address
            self.__log(event, msg)

#-- API calls -----------------------------------------------------------------

    # Track down heap memory freeing.

    def __remember_free(self, event, pc, ptr):
##        msg = "Code at %.08x freed heap block at %.08x" % (pc, ptr)
##        self.__log(event, msg)
        pid = event.get_pid()
        if self.processHeapLocation.has_key(pid):
            temp = self.processHeapLocation[pid]
            if temp.has_key(ptr):
                del temp[ptr]
            if not temp:
                del self.processHeapLocation[pid]

    def pre_HeapFree(self, event, ra, hHeap, dwFlags, lpMem):
        self.__remember_free(event, ra, lpMem)

    def pre_LocalFree(self, event, ra, hMem):
        self.__remember_free(event, ra, hMem)

    def pre_GlobalFree(self, event, ra, hMem):
        self.__remember_free(event, ra, hMem)

    def pre_free(self, event, ra, ptr):
        self.__remember_free(event, ra, ptr)

    # Track down heap memory allocations.

    def __remember_malloc(self, event, ptr):
        pid = event.get_pid()
        pc  = event.get_thread().get_pc()
##        msg = "Code at %.08x allocated heap block at %.08x" % (pc, ptr)
##        self.__log(event, msg)
        if not self.processHeapLocation.has_key(pid):
            self.processHeapLocation[pid] = dict()
        self.processHeapLocation[pid][ptr] = pc

    def post_HeapAlloc(self, event, retval):
        self.__remember_malloc(event, retval)

    def post_LocalAlloc(self, event, retval):
        self.__remember_malloc(event, retval)

    def post_GlobalAlloc(self, event, retval):
        self.__remember_malloc(event, retval)

    def post_malloc(self, event, retval):
        self.__remember_malloc(event, retval)

    # Track down heap memory re-allocations.

    def pre_HeapReAlloc(self, event, ra, hHeap, dwFlags, lpMem, dwBytes):
        self.__remember_free(event, lpMem)

    def pre_LocalReAlloc(self, event, ra, hMem, dwBytes, uFlags):
        self.__remember_free(event, hMem)

    def pre_GlobalReAlloc(self, event, ra, hMem, dwBytes, uFlags):
        self.__remember_free(event, hMem)

    def post_HeapReAlloc(self, event, retval):
        self.__remember_malloc(event, retval)

    def post_LocalReAlloc(self, event, retval):
        self.__remember_malloc(event, retval)

    def post_GlobalReAlloc(self, event, retval):
        self.__remember_malloc(event, retval)

#==============================================================================

def parse_cmdline(argv):
    'Parse the command line.'

    # Help message and version string
    version = (
              "Crash dumper using Win32DBG\n"
              "by Mario Vilas (mvilas at gmail.com)\n"
              "Version 1.0"
              )
    usage = (
            "\n"
            "\n"
            "  Create a new process (parameters for the target must be escaped):\n"
            "    %prog [options] -c <executable> [escaped parameters for the target]\n"
            "    %prog [options] -e <executable> [escaped parameters for the target]\n"
            "\n"
            "  Attach to a running process (by filename):\n"
            "    %prog [options] -a <executable>\n"
            "\n"
            "  Attach to a running process (by ID):\n"
            "    %prog [options] -a <process id>"
            )
##    formatter = optparse.IndentedHelpFormatter()
##    formatter = optparse.TitledHelpFormatter()
    parser = optparse.OptionParser(
                                    usage=usage,
                                    version=version,
##                                    formatter=formatter,
                                  )
    parser.add_option("-i", "--ignore-errors", action="store_true", default=False,
                      help="Ignore Python exceptions")

    # Commands
    commands = optparse.OptionGroup(parser, "Commands")
    commands.add_option("-a", "--attach", action="store_const",
                        dest="exec_mode", const="attach",
                        help="Attach to a running process")
    commands.add_option("-e", "--execute", action="store_const",
                        dest="exec_mode", const="execute",
                        help="Create a new windowed process")
    commands.add_option("-c", "--console", action="store_const",
                        dest="exec_mode", const="console",
                        help="Create a new console process [default]")
    parser.add_option_group(commands)

    # Debugging options
    debugging = optparse.OptionGroup(parser, "Debugging options")
##    debugging.add_option("-H", "--heap", action="store_true", default=False,
##                         help="Track down heap operations (may be slower)")
    debugging.add_option("-b", "--break-at", metavar="FILE",
                         help="Set code breakpoints from list file")
    debugging.add_option("-s", "--stalk-at", metavar="FILE",
                         help="Set one-shot code breakpoints from list file")
    parser.add_option_group(debugging)

    # Output options
    # TODO
    # * autogenerate a default crash dump file from the executable file
    output = optparse.OptionGroup(parser, "Output options")
    output.add_option("-v", "--verbose", action="store_true", default=True,
                      help="Log events to standard output [default]")
    output.add_option("-q", "--quiet", action="store_false", default=False, dest="verbose",
                      help="Do not log events to standard output")
    output.add_option("-f", "--file", default="crash.dat",
                      help="Specify a crash dump file [default: %default]")
    output.add_option("--no-crash-dump-file", action="store_true", default=False,
                      help="Supresses the use of a crash dump file")
    parser.add_option_group(output)

    # Parse and validate the command line options
    if len(argv) == 1:
        argv = argv + [ '--help' ]
    (options, args) = parser.parse_args(argv)
    options.heap = False            # XXX HACK remove when --heap is fully functional
    if options.exec_mode is None:
        options.exec_mode = "console"
    if options.exec_mode == "attach":
        if len(args) < 2:
            parser.error("executable filename or process id required for -a")
        if len(args) > 2:
            parser.error("no parameters can be passed to the executable when attaching")
    elif options.exec_mode in ("console", "execute"):
        if len(args) < 2:
            parser.error("executable filename required")
        if not os.path.exists(args[1]):
            try:
                args[1] = win32.SearchPath(None, args[1], None)[0]
            except WindowsError, e:
                parser.error("error searching for %s: %s" % (args[1], str(e)))
    else:
        raise AssertionError, "Internal error"
    if options.break_at:
        if not os.path.exists(options.break_at):
            parser.error("breakpoint list file not found: %s" % options.break_at)
        try:
            mixed_list   = HexInput.mixed_list_file(options.break_at)
            address_list = list()
            symbol_list  = list()
            for x in mixed_list:
                if type(x) == type(''):
                    symbol_list.append(x)
                elif type(x) == type(0):
                    address_list.append(x)
                else:
                    parser.error("invalid address in breakpoint list file: %r" % x)
            options.break_at = (address_list, symbol_list)
        except ValueError, e:
            parser.error(str(e))
    if options.stalk_at:
        if not os.path.exists(options.stalk_at):
            parser.error("one-shot breakpoint list file not found: %s" % options.stalk_at)
        try:
            mixed_list   = HexInput.mixed_list_file(options.stalk_at)
            address_list = list()
            symbol_list  = list()
            for x in mixed_list:
                if type(x) == type(''):
                    symbol_list.append(x)
                elif type(x) == type(0):
                    address_list.append(x)
                else:
                    parser.error("invalid address in one-shot breakpoint list file: %r" % x)
            options.stalk_at = (address_list, symbol_list)
        except ValueError, e:
            parser.error(str(e))

    # return the parsed command line options and arguments
    return (options, args)

# TODO
# * Create a new crash dump file for each debugged executable
def main(args):
    (options, args) = parse_cmdline(args)

    if options.verbose:
        print DebugLog.log_text("Crash logger started, %s" % time.ctime())

    # Create the event handler
    oldCrashCount = 0
    eventHandler  = LoggingEventHandler(options)
    if not options.no_crash_dump_file:
        try:
            if os.path.exists(options.file):
                eventHandler.knownCrashes.load(options.file)
                oldCrashCount = len(eventHandler.knownCrashes)
                if options.verbose:
                    msg = "Crash dump file found, loaded %d crashes"
                    msg = msg % oldCrashCount
                    print DebugLog.log_text(msg)
        except Exception, e:
            if options.verbose:
                traceback.print_exc()
                print

    # Create the debug object
    debug = Debug(eventHandler)
    if   options.exec_mode == "execute":
        lpCmdLine   = debug.system.argv_to_cmdline(args[1:])
        mainProcess = debug.start(lpCmdLine, bFollow = True, bConsole = False)
    elif options.exec_mode == "console":
        lpCmdLine   = debug.system.argv_to_cmdline(args[1:])
        mainProcess = debug.start(lpCmdLine, bFollow = True, bConsole = True)
    elif options.exec_mode == "attach":
        try:
            dwProcessId = HexInput.integer( args[1] )
        except ValueError:
            s = System()
            s.scan_processes()
            pl = s.find_processes_by_filename(args[1])
            if not pl:
                parser.error( "process not found: %s" % args[1] )
            if len(pl) > 1:
                msg = "multiple processes found for %s\n" % args[1]
                for p,n in pl:
                    msg += "\t%12d: %s\n" % (p,n)
                parser.error(msg)
            dwProcessId = pl[0][0].get_pid()
        mainProcess = debug.attach(dwProcessId)
    else:
        raise AssertionError, "Internal error"

    # Main debugging loop
    try:
        while debug.system.get_process_count():
            try:
                event = debug.wait(1000)
            except WindowsError, e:
                if e.winerror == win32.ERROR_SEM_TIMEOUT:
                    continue
                raise
            try:
                debug.dispatch(event)
            except Exception:
                if options.ignore_errors:
                    if options.verbose:
                        traceback.print_exc()
                else:
                    raise
            debug.cont(event)
    finally:
        if not options.no_crash_dump_file:
            newCrashCount = len(eventHandler.knownCrashes)
            if newCrashCount - oldCrashCount:
                if options.verbose:
                    if oldCrashCount:
                        msg = "Saving %d (%d new) crashes to crash dump file..."
                        msg = msg % (newCrashCount, newCrashCount - oldCrashCount)
                    else:
                        msg = "Saving %d crashes to crash dump file..."
                        msg = msg % newCrashCount
                    print DebugLog.log_text(msg)
                eventHandler.knownCrashes.save(options.file)
        if options.verbose:
            print DebugLog.log_text("Crash logger stopped, %s" % time.ctime())

if __name__ == '__main__':
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    main(sys.argv)
