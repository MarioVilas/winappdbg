#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  http://tinyurl.com/nicolaseconomou

# sehtest: Bruteforce valid addresses for an SEH overwrite buffer overflow
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
from winappdbg import HexInput, HexDump, CrashDump, Logger

#------------------------------------------------------------------------------

# XXX TODO
# * log exceptions instead of stopping everything!
# * filter out syscalls not issued from within the exception handling code in
#   ntdll.dll (to avoid unwanted side effects)

def ExecutableAddressIterator(memory_map):
    for mbi in memory_map:
        if mbi.is_executable():
            BaseAddress = mbi.BaseAddress
            RegionSize  = mbi.RegionSize
            for address in xrange(BaseAddress, BaseAddress + RegionSize):
                yield address

class Test( object ):
    def __init__(self, options, logger):
        self.options = options
        self.logger  = logger
        self.testing = False
        self.seh     = None
        self.orig    = None
        self.last    = None
        self.context = None
        self.memory  = None

    def exception(self, event):
        if not self.testing:
            self.logExceptionEvent(event)
            self.checkExceptionChain(event)
        if self.testing:    # don't use elif here!
            self.nextExceptionHandler(event)

    def logExceptionEvent(self, event):
        what  = event.get_exception_name()
        where = HexDump.address( event.get_exception_address() )
        msg   = "Caught %s at %s" % (what, where)
        self.logger.log_event(event, msg)

    def checkExceptionChain(self, event):

        # XXX TODO
        # + Add a list of exceptions to ignore
        # + Option to ignore first chance exceptions
        # + Option to fail on missing SEH chain

        thread  = event.get_thread()
        process = event.get_process()
        target  = self.options.seh
        if target:
            chain = thread.get_seh_chain()
            if chain:
                index = 0
                for (_, address) in chain:
                    if address == target:
                        if index > 0:
                            self.seh = chain[index - 1][0]
                        else:
                            self.seh = thread.get_seh_chain_pointer()
                        break
                    index += 1
            else:
                self.seh = thread.get_seh_chain_pointer()
        else:
            self.seh = thread.get_seh_chain_pointer()

        if self.seh:
            self.orig     = process.read_pointer(self.seh + 4)
            self.context  = thread.get_context()
            self.memory   = process.take_memory_snapshot()
            self.iterator = ExecutableAddressIterator(self.memory)
            self.testing  = True

            self.showBruteforceBanner(event)

    def showBruteforceBanner(self, event):
        count = 0
        first = 0
        last  = 0
        for mbi in self.memory:
            if mbi.is_executable():
                count = count + mbi.RegionSize
                address = mbi.BaseAddress
                if first == 0:
                    first = address
                if last < address:
                    last = address
        msg   = "Bruteforcing %d addresses (%s-%s)..."
        first = HexDump.address(first)
        last  = HexDump.address(last)
        self.logger.log(msg % (count, first, last))

    def nextExceptionHandler(self, event):
        debug   = event.debug
        process = event.get_process()
        thread  = event.get_thread()
        pid     = process.get_pid()

        thread.set_context(self.context)
        process.restore_memory_snapshot(self.snapshot)

        try:
            address = self.iterator.next()
        except StopIteration:
            process.write_pointer(self.seh + 4, self.orig)
            event.debug.detach( event.get_pid() )
            raise

        msg = HexDump.address( event.get_exception_address() )
        msg = "Trying %s" % msg
        self.logger.log_text(msg)

        if self.last:
            debug.dont_break_at(pid, self.last)
        process.write_pointer(self.seh + 4, address)
        debug.break_at(pid, address, self.foundValidHandler)
        self.last = address

    def foundValidHandler(self, event):
        address = HexDump.address( event.get_exception_address() )
        self.logger.log_text("Found %s" % address)
        self.nextExceptionHandler()

class Handler( EventHandler ):

    def __init__(self, options):
        super(Handler, self).__init__()
        self.options = options
        self.test    = dict()   # pid -> Test
        self.logger  = Logger()

    def exception(self, event):
##        try:
            pid = event.get_pid()
            if not self.test.has_key(pid):
                self.test[pid] = test = Test(self.options, self.logger)
            else:
                test = self.test[pid]
            try:
                test.exception(event)
            except StopIteration:
                del self.test[pid]
##        except Exception:
##            self.logger.log_exc()

#------------------------------------------------------------------------------

def main( argv ):

    # Parse the command line arguments
    options = parse_cmdline(argv)

    # Create the event handler object
    eventHandler = Handler(options)

    # Create the debug object
    debug = Debug(eventHandler, bKillOnExit = not options.autodetach)
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

    # SEH test options
    sehtest = optparse.OptionGroup(parser, "SEH Test options")
    sehtest.add_option("--seh", metavar="ADDRESS",
                       help="address of SEH handler function to hijack [default: 0x41414141]")
    parser.add_option_group(sehtest)

    # Debugging options
    debugging = optparse.OptionGroup(parser, "Debugging options")
    debugging.add_option("--autodetach", action="store_true",
                  help="automatically detach from debugees on exit [default]")
    debugging.add_option("--follow", action="store_true",
                  help="automatically attach to child processes [default]")
    debugging.add_option("--dont-autodetach", action="store_false",
                                                         dest="autodetach",
                  help="don't automatically detach from debugees on exit")
    debugging.add_option("--dont-follow", action="store_false",
                                                             dest="follow",
                  help="don't automatically attach to child processes")
    parser.add_option_group(debugging)

    # Defaults
    parser.set_defaults(
        autodetach  = True,
        follow      = True,
        windowed    = list(),
        console     = list(),
        attach      = list(),
        verbose     = True,
        seh         = '0x41414141',
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

    # Validate the SEH test options
    try:
        options.seh = HexInput.address(options.seh)
    except ValueError:
        parser.error("invalid address for --seh: %s" % options.seh)

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
