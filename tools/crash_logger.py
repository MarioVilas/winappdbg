#!~/.wine/drive_c/Python25/python.exe

# Crash logger
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

__revision__ = "$Id$"

__all__ =   [
                'LoggingEventHandler',
            ]

import winappdbg
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

    # Regular expression to extract 8 digit hexadecimal numbers.
    re_hexa = re.compile('[0-9A-F]' * 8, re.I)

    def __init__(self, options):

        # Copy the user-defined options.
        self.options = options

        # Create the crash container.
        if not options.nodb:
            self.knownCrashes = CrashContainer( options.file )
        else:
            self.knownCrashes = CrashContainer()

        # Create the cache of resolved labels.
        self.labelsCache = dict()                   # pid -> label -> address

        # Call the base class constructor.
        super(LoggingEventHandler, self).__init__()

    def __log(self, event, text):
        if self.options.verbose:
            print DebugLog.log_event(event, text)

    def __get_location(self, event, address):
        label = event.get_process().get_label_at_address(address)
        if label:
            return label
        return '0x%.8x' % address

    def __set_breakpoints(self, event):
        method = event.debug.break_at
        bplist = self.options.break_at
        self.__set_breakpoints_from_list(event, bplist, method)
        method = event.debug.stalk_at
        bplist = self.options.stalk_at
        self.__set_breakpoints_from_list(event, bplist, method)

    def __set_breakpoints_from_list(self, event, bplist, method):
        dwProcessId = event.get_pid()
        aModule     = event.get_module()
        for label in bplist:
            if dwProcessId not in self.labelsCache:
                self.labelsCache[dwProcessId] = dict()
            if label not in self.labelsCache[dwProcessId]:
                try:
                    address = aModule.resolve_label(label)
                except ValueError, e:
                    address = None
                except RuntimeError, e:
                    address = None
                except WindowsError, e:
                    address = None
                if address is not None:
                    self.labelsCache[dwProcessId][label] = address
                    try:
                        method(dwProcessId, address)
                    except RuntimeError:
                        pass
                    except WindowsError:
                        pass

#-- Events --------------------------------------------------------------------

    # Handle all events not handled by the following class methods.
    def event(self, event):

        # Generate a crash object.
        crash = Crash(event)

        # Log the event to standard output.
        if self.options.verbose:
            if crash not in self.knownCrashes:
                msg = crash.fullReport()
            else:
                msg = crash.briefReport()
            self.__log(event, msg)

        # Add the crash object to the container.
        self.knownCrashes.add(crash)

    # Handle the create process events.
    def create_process(self, event):

        # Set user-defined breakpoints for this process.
        try:
            self.__set_breakpoints(event)

        # Log the event to standard output.
        finally:
            if self.options.verbose:
                lpStartAddress = event.get_start_address()
                szFilename = event.get_filename()
                if not szFilename:
                    szFilename = Module.unknown
                if lpStartAddress:
                    where = HexOutput.address(lpStartAddress)
                    msg = "Process %s started, entry point at %s"
                    msg = msg % (szFilename, where)
                else:
                    msg = "Attached to process %s" % szFilename
                self.__log(event, msg)

    # Handle the create thread events.
    def create_thread(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            lpStartAddress = event.get_start_address()
            if lpStartAddress:
                where = self.__get_location(event, lpStartAddress)
                msg   = "Thread started, entry point at %s" % where
            else:
                msg   = "Attached to thread"
            self.__log(event, msg)

    # Handle the load dll events.
    def load_dll(self, event):
        dwProcessId = event.get_pid()
        aModule     = event.get_module()

        # Set user-defined breakpoints for this module.
        try:
            self.__set_breakpoints(event)

        # Log the event to standard output.
        finally:
            lpBaseOfDll = aModule.get_base()
            fileName    = aModule.get_filename()
            if fileName:
                if self.options.verbose:
                    msg = "Loaded %s at 0x%.8x" % (fileName, lpBaseOfDll)
                    self.__log(event, msg)
            else:
                if self.options.verbose:
                    msg = "Loaded a new module at 0x%.8x" % lpBaseOfDll
                    self.__log(event, msg)

    # Handle the exit process events.
    def exit_process(self, event):

        # Clear the labels cache for this process.
        dwProcessId = event.get_pid()
        if dwProcessId in self.labelsCache:
            del self.labelsCache[dwProcessId]

        # Log the event to standard output.
        if self.options.verbose:
            msg = "Process terminated, exit code 0x%x" % event.get_exit_code()
            self.__log(event, msg)

    # Handle the exit thread events.
    def exit_thread(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            msg = "Thread terminated, exit code 0x%x" % event.get_exit_code()
            self.__log(event, msg)

    # Handle the unload dll events.
    def unload_dll(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            aModule     = event.get_module()
            lpBaseOfDll = aModule.get_base()
            fileName    = aModule.get_filename()
            if not fileName:
                fileName = 'a module'
            self.__log(event, "Unloaded %s at %.8x" % (fileName, lpBaseOfDll))

    # Handle the debug output string events.
    def output_string(self, event):

        # Generate a crash object.
        crash = Crash(event)

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
        if self.options.verbose:
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

    # Ignore unknown (most likely C++) exceptions.
    def unknown_exception(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            desc    = event.get_exception_description()
            address = event.get_exception_address()
            self.__log(event, "%s at 0x%.8x" % (desc, address))

    # Ignore Microsoft Visual C exceptions.
    def ms_vc_exception(self, event):

        # Log the event to standard output.
        if self.options.verbose:
            desc    = event.get_exception_description()
            address = event.get_exception_address()
            self.__log(event, "%s at 0x%.8x" % (desc, address))

    # Handle single step events.
    def single_step(self, event):

        # Continue without setting the trap flag.
        event.continueStatus = win32.DBG_CONTINUE

        # Log the event to standard output.
        if self.options.verbose:
            address = event.get_exception_address()
            where   = self.__get_location(event, address)
            msg     = "Single step event at %s" % where
            self.__log(event, msg)

    # Handle breakpoints events.
    def breakpoint(self, event):

        # Step over breakpoints.
        # This includes both user-defined and hardcoded in the binary.
        event.continueStatus = win32.DBG_CONTINUE

        # Log the event to standard output.
        if self.options.verbose:
            aProcess = event.get_process()
            address  = event.get_exception_address()
            where    = self.__get_location(event, address)
            if aProcess.is_system_defined_breakpoint(address):
                msg = "System breakpoint hit (%s)" % where
            else:
                msg = "Breakpoint event at %s" % where
            self.__log(event, msg)

#==============================================================================

def parse_cmdline(argv):
    'Parse the command line.'

    # Help message and version string
    version = (
              "WinAppDbg crash logger\n"
              "by Mario Vilas (mvilas at gmail.com)\n"
              "%s\n"
              ) % winappdbg.version
    usage = (
            "\n"
            "\n"
            "  Create a new process (parameters for the target must be escaped):\n"
            "    %prog [options] -c <executable> [parameters for the target]\n"
            "    %prog [options] -e <executable> [parameters for the target]\n"
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
    commands.add_option("-a", "--attach", action="append",
                        help="Attach to a running process")
    commands.add_option("-w", "--windowed", action="append",
                        help="Create a new windowed process")
    commands.add_option("-c", "--console", action="append",
                        help="Create a new console process [default]")
    parser.add_option_group(commands)

    # Debugging options
    debugging = optparse.OptionGroup(parser, "Debugging options")
    debugging.add_option("-b", "--break-at", metavar="FILE",
                         help="Set code breakpoints from list file")
    debugging.add_option("-s", "--stalk-at", metavar="FILE",
                         help="Set one-shot code breakpoints from list file")
    parser.add_option_group(debugging)

    # Output options
    # TODO
    # * autogenerate a default crash dump file from the executable file
    output = optparse.OptionGroup(parser, "Output options")
    output.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      help="Log events to standard output [default]")
    output.add_option("-q", "--quiet", action="store_false", dest="verbose",
                      help="Do not log events to standard output")
    output.add_option("-f", "--file", default="crashes.db",
                      help="Specify a crash dump file [default: %default]")
    output.add_option("--nodb", "--no-crash-dump-file", action="store_true",
                      default=False,
                      help="Supresses the use of a crash dump file")
    parser.add_option_group(output)

    # Defaults
    parser.set_defaults(
        verbose     = True,
        windowed    = list(),
        console     = list(),
        attach      = list(),
    )

    # Parse and validate the command line options
    if len(argv) == 1:
        argv = argv + [ '--help' ]
    (options, args) = parser.parse_args(argv)
    args = args[1:]
    if not options.windowed and not options.console and not options.attach:
        options.console = args
    else:
        if args:
            parser.error("don't know what to do with extra parameters: %s" % args)

    # Get the list of attach targets
    system = System()
    system.scan_processes()
    attach_targets = list()
    for token in options.attach:
        try:
            dwProcessId = HexInput.integer(token)
        except ValueError:
            dwProcessId = None
        if dwProcessId is not None:
            if not system.has_process(dwProcessId):
                parser.error("can't find process %d" % dwProcessId)
            try:
                process = Process(dwProcessId)
                process.open_handle()
                process.close_handle()
            except WindowsError, e:
                parser.error("can't open process %d: %s" % (dwProcessId, e))
            attach_targets.append(dwProcessId)
        else:
            for process, name in system.find_processes_by_filename(token):
                dwProcessId = process.get_pid()
                try:
                    process = Process(dwProcessId)
                    process.open_handle()
                    process.close_handle()
                except WindowsError, e:
                    parser.error("can't open process %d: %s" % (dwProcessId, e))
                attach_targets.append( process.get_pid() )
    options.attach = attach_targets

    # Get the list of console programs to execute
    console_targets = list()
    for token in options.console:
        vector = system.cmdline_to_argv(token)
        if not vector:
            parser.error("bad use of --console")
        filename = vector[0]
        if not os.path.exists(filename):
            try:
                filename = win32.SearchPath(None, filename, '.exe')[0]
            except WindowsError, e:
                parser.error("error searching for %s: %s" % (filename, str(e)))
            vector = ( filename, ) + vector[1:]
            token  = system.argv_to_cmdline(vector)
        console_targets.append(token)
    options.console = console_targets

    # Get the list of windowed programs to execute
    windowed_targets = list()
    for token in options.windowed:
        vector = system.cmdline_to_argv(token)
        if not vector:
            parser.error("bad use of --windowed")
        filename = vector[0]
        if not os.path.exists(filename):
            try:
                filename = win32.SearchPath(None, filename, '.exe')[0]
            except WindowsError, e:
                parser.error("error searching for %s: %s" % (filename, str(e)))
            vector[0] = filename
            token     = system.argv_to_cmdline(vector)
        windowed_targets.append(token)
    options.windowed = windowed_targets

    # If no targets were set at all, show an error message
    if not options.attach and not options.console and not options.windowed:
        parser.error("no targets found!")

    # Get the list of breakpoints to set
    if options.break_at:
        if not os.path.exists(options.break_at):
            parser.error("breakpoint list file not found: %s" % options.break_at)
        try:
            options.break_at = HexInput.string_list_file(options.break_at)
        except ValueError, e:
            parser.error(str(e))
    else:
        options.break_at = list()

    # Get the list of one-shot breakpoints to set
    if options.stalk_at:
        if not os.path.exists(options.stalk_at):
            parser.error("one-shot breakpoint list file not found: %s" % options.stalk_at)
        try:
            options.stalk_at = HexInput.string_list_file(options.stalk_at)
        except ValueError, e:
            parser.error(str(e))
    else:
        options.stalk_at = list()

    # Return the parsed command line options and arguments
    return (parser, options, args)

# TODO
# * Create a new crash dump file for each debugged executable
def main(args):
    (parser, options, args) = parse_cmdline(args)

    if options.verbose:
        print DebugLog.log_text("Crash logger started, %s" % time.ctime())

    # Create the event handler
    oldCrashCount = 0
    eventHandler  = LoggingEventHandler(options)

    # Create the debug object
    debug = Debug(eventHandler)
    try:

        # Attach to the targets
        for dwProcessId in options.attach:
            debug.attach(dwProcessId)
        for lpCmdLine in options.console:
            debug.execl(lpCmdLine, bConsole = True)
        for lpCmdLine in options.windowed:
            debug.execl(lpCmdLine, bConsole = False)

        # Main debugging loop
        while debug.get_debugee_count() > 0:
            try:
                event = debug.wait()
            except Exception:
                if not options.ignore_errors and options.verbose:
                    traceback.print_exc()
                raise   # don't ignore this error
            try:
                try:
                    debug.dispatch(event)
                finally:
                    debug.cont(event)
            except Exception:
                if not options.ignore_errors:
                    if options.verbose:
                        traceback.print_exc()
                    raise
    finally:
        try:
            debug.stop(bIgnoreExceptions = options.ignore_errors)
        finally:
            if options.verbose:
                print DebugLog.log_text("Crash logger stopped, %s" % time.ctime())

if __name__ == '__main__':
    try:
        import psyco
        psyco.full()
    except ImportError:
        pass
    main(sys.argv)
