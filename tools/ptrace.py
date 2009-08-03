#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.

# Process execution tracer
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

import os
import sys
import optparse

import winappdbg
from winappdbg import win32
from winappdbg import Debug, EventHandler, System, Process
from winappdbg import HexInput, HexDump, CrashDump

#------------------------------------------------------------------------------

class Tracer( EventHandler ):

    # Trace mode
    def __trace(self, event):
        if self.options.mode in ("trace", "branch"):
            event.debug.start_tracing( event.get_tid() )
            self.__branch(event)

    # Branch mode
    def __branch(self, event):
        if self.options.mode == "branch":
            event.debug.system.enable_step_on_branch_mode()

    # Syscall mode
    def __syscall(self, event):
        if self.options.mode == "syscall":
            pid    = event.get_pid()
            module = event.get_module()
            if module.match_name("ntdll"):
                event.debug.break_at( pid, module.resolve("KiIntSystemCall"),
                                                      self.KiIntSystemCall )
                event.debug.break_at( pid, module.resolve("KiFastSystemCall"),
                                                      self.KiFastSystemCall )

    # Dump the execution context
    def __dump(self, event, label = None):
        thread = event.get_thread()
        trace  = thread.get_stack_trace_with_labels()
        ctx    = thread.get_context(win32.CONTEXT_FULL)
        if not label:
            label = thread.get_label_at_pc()
        print label
        print CrashDump.dump_registers(ctx)
        print CrashDump.dump_stack_trace_with_labels(trace),
        print "-" * 79

    # Disassemble the current instruction
    def __disasm(self, event):
        thread  = event.get_thread()
        tid     = event.get_tid()
        pc      = thread.get_pc()
        code    = thread.disassemble( pc, 0x10 ) [0]
        line    = CrashDump.dump_code_line(code, dwDumpWidth=8*2)
        print "~%d %s" % ( tid, line )

    # Events

    def create_process( self, event ):
        self.__trace(event)

    def create_thread( self, event ):
        self.__trace(event)

    def load_dll( self, event ):
        self.__syscall(event)

    def single_step( self, event ):
        self.__branch(event)
        self.__disasm(event)

    # Breakpoints

    def KiIntSystemCall( self, event ):
        self.__dump(event, "ntdll!KiIntSystemCall")

    def KiFastSystemCall( self, event ):
        self.__dump(event, "ntdll!KiFastSystemCall")

#------------------------------------------------------------------------------

def main( argv ):

    # Parse the command line arguments
    options = parse_cmdline(argv)

    # Create the event handler object
    eventHandler = Tracer()
    eventHandler.options = options

    # Create the debug object
    debug = Debug(eventHandler,
                                bKillOnExit  = not options.autodetach,
                                bHostileCode = options.hostile)
    try:

        # Attach to the targets
        for dwProcessId in options.attach:
            debug.attach(dwProcessId)
        for lpCmdLine in options.console:
            debug.execl(lpCmdLine, bConsole = True,  bFollow = options.follow)
        for lpCmdLine in options.windowed:
            debug.execl(lpCmdLine, bConsole = False, bFollow = options.follow)

        # Run the debug loop
        debug.loop()

    # Stop the debugger
    finally:
        debug.stop()

#------------------------------------------------------------------------------

def parse_cmdline( argv ):

    # Help message and version string
    version = (
              "Process execution tracer\n"
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

    # Commands
    commands = optparse.OptionGroup(parser, "Commands")
    commands.add_option("-a", "--attach", action="append",
                        help="Attach to a running process")
    commands.add_option("-w", "--windowed", action="append",
                        help="Create a new windowed process")
    commands.add_option("-c", "--console", action="append",
                        help="Create a new console process [default]")
    parser.add_option_group(commands)

    # Tracing options
    tracing = optparse.OptionGroup(parser, "Tracing options")
    tracing.add_option("--trace", action="store_const", const="trace",
                                                               dest="mode",
                      help="Set the single step mode [default]")
    tracing.add_option("--branch", action="store_const", const="branch",
                                                               dest="mode",
                      help="Set the step-on-branch mode")
    tracing.add_option("--syscall", action="store_const", const="syscall",
                                                               dest="mode",
                      help="Set the syscall trap mode")
    parser.add_option_group(tracing)

    # Debugging options
    debugging = optparse.OptionGroup(parser, "Debugging options")
    debugging.add_option("--autodetach", action="store_true",
                  help="automatically detach from debugees on exit [default]")
    debugging.add_option("--follow", action="store_true",
                  help="automatically attach to child processes [default]")
    debugging.add_option("--trusted", action="store_false", dest="hostile",
                  help="treat debugees as trusted code [default]")
    debugging.add_option("--dont-autodetach", action="store_false",
                                                         dest="autodetach",
                  help="don't automatically detach from debugees on exit")
    debugging.add_option("--dont-follow", action="store_false",
                                                             dest="follow",
                  help="don't automatically attach to child processes")
    debugging.add_option("--hostile", action="store_true",
                  help="treat debugees as hostile code")
    parser.add_option_group(debugging)

    # Defaults
    parser.set_defaults(
        autodetach  = True,
        follow      = True,
        hostile     = False,
        windowed    = list(),
        console     = list(),
        attach      = list(),
        mode        = "trace",
    )

    # Parse and validate the command line options
    if len(argv) == 1:
        argv = argv + [ '--help' ]
    (options, args) = parser.parse_args(argv)
    args = args[1:]
    if not options.windowed and not options.console and not options.attach:
        options.console = [ System.argv_to_cmdline(args) ]
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
            vector[0] = filename
            token     = system.argv_to_cmdline(vector)
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

    return options

#------------------------------------------------------------------------------

if __name__ == "__main__":
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main(sys.argv)
