#!~/.wine/drive_c/Python25/python.exe

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.

# Exploit return address bruteforcer
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
from winappdbg import Debug, EventHandler, System, Process, MemoryAddresses
from winappdbg import HexInput, HexDump, CrashDump

#------------------------------------------------------------------------------

# no puedo poner hwbp asi que espero a que salte una excepcion
# cuando empiezo a bruteforcear:
#   * pongo el thread en modo trace
#   * pongo 1s membp en todas las paginas escribibles
#   * cuando salta un membp leo la data y continuo
#   * cuando salta single step:
#       * me fijo si ya llegue al destino
#       * incremento el contador
#       * paro al llegar a una instruccion prohibida
#       * paro al llegar al maximo del contador
#   * cuando paro:
#       * restauro las paginas modificadas
#       * restauro el contexto del thread (ojo no apagar tf)
#       * pongo el proximo eip
#       * pongo de vuelta los breakpoints que me falten

class ProcessBruteforce( object ):

    MAX_INSTRUCTIONS = 10

    def __init__(self, event):
        super(ProcessBruteforce, self).__init__()
        self.debug       = event.debug
        self.process     = event.get_process()
        self.thread      = event.get_thread()
        self.memory_map  = list()
        self.saved_pages = dict()
        self.address     = 0
        self.counter     = 0

    def get_process(self):
        return self.process

    def get_thread(self):
        return self.thread

    def get_pid(self):
        return self.get_process().get_pid()

    def get_tid(self):
        return self.get_thread().get_tid()

    # Set page breakpoints on each writeable page.
    # That way we can track down write accesses,
    # in order to reverse them later.
    def set_page_breakpoints(self):
        debug = self.debug
        for mbi in self.memory_map:
            if mbi.is_writeable():
                pid  = self.get_pid()
                base = mbi.BaseAddress
                for offset in xrange(0, mbi.RegionSize, System.pageSize):
                    address = base + offset
                    if not debug.has_page_breakpoint(pid, address):
                        debug.define_page_breakpoint(pid, address, 1)
                    try:
                        debug.enable_one_shot_page_breakpoint(pid, address)
                    except WindowsError:
                        print "error setting breakpoint at %s" % HexDump.address(address)
                        pass
                        # for calc.exe these pages raise exceptions:
                        # 00030000
                        # 003b0000
                        # 7ffda000
                        # 7ffdf000

    # Remove all the page breakpoints we set in this process.
    def remove_page_breakpoints(self):
        debug = self.debug
        pid   = self.get_pid()
        for bp in debug.get_process_page_breakpoints(pid):
            debug.erase_page_breakpoint(pid, bp.get_address())

    # Save the memory contents on each access to a writeable page.
    # This will happen on read accesses too - but we don't care,
    # since having the same breakpoint hit many times is more costly
    # than restoring an extra memory page.
    def notify_guard_page(self, event):
        pid = self.get_pid()
        if event.get_pid() == pid:
            address = event.get_fault_address()
            address = MemoryAddresses.align_address_to_page_start(address)
            if self.debug.has_page_breakpoint(pid, address):
                data = self.get_process().read(address, System.pageSize)
                self.saved_pages[address] = data
        return True

    # Restore the original contents of modified memory pages.
    def restore_pages(self):
        process = self.get_process()
        for address, data in self.saved_pages.iteritems():
            process.write(address, data)
        self.saved_pages = dict()

    # Save the thread's context.
    # Since we're calling this after start_tracing() the trap flag
    # will be set when we call restore_context().
    def save_context(self):
        self.context = self.get_thread().get_context()

    # Restore the thread's context.
    # The trap flag is already set becase we call save_context()
    # right after we start tracing the thread.
    def restore_context(self):
        self.get_thread().set_context(self.context)

    # Stop on forbidden instructions.
    # Remove all prefixes first.
    prefixes  = '\x26\x2e\x3e\x64\x65\x66\x67\xf0\xf2\xf3'
    forbidden = '\xcd'                                              # XXX TODO
    def is_forbidden_opcode(self, code):
        for prefix in self.prefixes:
            code = code.replace(prefix, '')
        return code and code[0] in self.forbidden

    # Stop when the shellcode area is reached.
    def is_shellcode(self, address):
        return False                                                 # XXX TODO

    # Stop on exceptions.
    def notify_exception(self, event):
        bContinue = self.next_address()
        if bContinue:
            event.continueStatus = win32.DBG_EXCEPTION_HANDLED
        else:
            event.continueStatus = win32.DBG_EXCEPTION_NOT_HANDLED
        return bContinue

    # Trace execution for each bruteforced return address.
    # Try the next address when the shellcode area is reached,
    # when an invalid opcode is reached, or the maximum number
    # of instructions was executed.
    def notify_single_step(self, event):
        pid = event.get_pid()
        if pid == self.get_pid() and self.debug.is_tracing(event.get_tid()):
            address = self.get_thread().get_pc()
            if self.is_shellcode(address):
                print "Found! %s" % HexDump.address(self.address)
                return self.next_address()
            self.counter += 1
            if self.counter > self.MAX_INSTRUCTIONS:
                return self.next_address()
            code = self.get_process().read(address, 15)
            if self.is_forbidden_opcode(code):
                return self.next_address()
        return True

    # Build a list of target ranges to try.
    def calculate_target_addresses(self):
        self.target_ranges = list()
        for mbi in self.memory_map:
##            if mbi.is_executable(mbi):
            if mbi.is_readable(mbi):
                start = mbi.BaseAddress
                end   = start + mbi.RegionSize
                self.target_ranges.append( iter(xrange(start, end, 1)) )

    # Try the next address.
    def next_address(self):
        self.counter = 0
        while 1:
            if not self.target_ranges:
                self.stop_searching()
                return False
            try:
                self.address = self.target_ranges[0].next()
                break
            except StopIteration:
                self.target_ranges.pop(0)
        print "Trying %s" % HexDump.address(self.address)
        self.restore_pages()
        self.restore_context()
        self.set_page_breakpoints()
        self.get_thread().set_pc(self.address)
        return True

    # Start bruteforcing return addresses.
    def start_searching(self):
        process = self.get_process()
        process.suspend()
        self.memory_map = process.get_memory_map()
        self.calculate_target_addresses()
        self.set_page_breakpoints()
        self.debug.start_tracing(self.get_tid())
        self.save_context()
        self.get_thread().resume()

    # We tried all possible addresses.
    def stop_searching(self):
        self.remove_page_breakpoints()
        self.restore_pages()
        self.restore_context()
        self.debug.stop_tracing(self.get_tid())
        self.get_thread().suspend()
        self.get_process().resume()

class DebugSessionBruteforce( EventHandler ):

    def __init__(self, options):
        super(DebugSessionBruteforce, self).__init__()
        self.__options     = options
        self.__bruteforcer = set()

    def create_process(self, event):
##        print event.get_event_name()            # XXX DEBUG
        self.__trap_trigger(event)

    def create_thread(self, event):
##        print event.get_event_name()            # XXX DEBUG
        self.__trap_trigger(event)

    def single_step(self, event):
##        print event.get_exception_description() # XXX DEBUG
        to_remove = set()
        for bruteforcer in self.__bruteforcer:
            if not bruteforcer.notify_single_step(event):
                to_remove.add(bruteforcer)
        self.__bruteforcer.difference_update(to_remove)

    def guard_page(self, event):
##        print event.get_exception_description() # XXX DEBUG
        to_remove = set()
        for bruteforcer in self.__bruteforcer:
            if not bruteforcer.notify_guard_page(event):
                to_remove.add(bruteforcer)
        self.__bruteforcer.difference_update(to_remove)

    def exception(self, event):
##        print event.get_exception_description() # XXX DEBUG
        to_remove = set()
        for bruteforcer in self.__bruteforcer:
            if not bruteforcer.notify_exception(event):
                to_remove.add(bruteforcer)
        self.__bruteforcer.difference_update(to_remove)

    def __trap_trigger(self, event):
##        print "trap"
        debug   = event.debug
        process = event.get_process()
        address = process.resolve_label(self.__options.trigger)

##        print "address", hex(address)

##        tid     = event.get_tid()
##        print "tid", tid

##        for tid in process.iter_thread_ids():
##            print "tid", tid
##            debug.define_hardware_breakpoint(tid, address,
##                                             debug.BP_BREAK_ON_EXECUTION,
##                                             debug.BP_WATCH_BYTE,
##                                             True, self.__hit_trigger)
##            debug.enable_one_shot_hardware_breakpoint(tid, address)

        debug.stalk_at(event.get_pid(), address, self.__hit_trigger)

    def __hit_trigger(self, event):
##        print "hit"
        pid     = event.get_pid()
        tid     = event.get_tid()
##        print "pid", pid, "tid", tid

        bruteforcer = ProcessBruteforce(event)
        self.__bruteforcer.add(bruteforcer)
        bruteforcer.start_searching()

#------------------------------------------------------------------------------

def main( argv ):

    # Parse the command line arguments
    options = parse_cmdline(argv)

    # Create the event handler object
    eventHandler = DebugSessionBruteforce(options)

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
              "Exploit return address bruteforcer\n"
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

    # Trigger options
    trigger = optparse.OptionGroup(parser, "Trigger options")
    trigger.add_option("--trigger", metavar="ADDRESS",
                       help="Source address range (when the bug is triggered), default is 0x41414141")
    trigger.add_option("--shellcode", metavar="ADDRESS-ADDRESS",
                       help="Destination address range (where the shellcode goes), default is [ESP+8]")
    parser.add_option_group(trigger)

    # Debugging options
    debugging = optparse.OptionGroup(parser, "Debugging options")
##    debugging.add_option("--autodetach", action="store_true",
##                  help="automatically detach from debugees on exit [default]")
    debugging.add_option("--follow", action="store_true",
                  help="automatically attach to child processes [default]")
##    debugging.add_option("--trusted", action="store_false", dest="hostile",
##                  help="treat debugees as trusted code [default]")
##    debugging.add_option("--dont-autodetach", action="store_false",
##                                                         dest="autodetach",
##                  help="don't automatically detach from debugees on exit")
    debugging.add_option("--dont-follow", action="store_false",
                                                             dest="follow",
                  help="don't automatically attach to child processes")
##    debugging.add_option("--hostile", action="store_true",
##                  help="treat debugees as hostile code")
    parser.add_option_group(debugging)

    # Defaults
    parser.set_defaults(
        autodetach  = False,
        follow      = True,
        hostile     = False,
        windowed    = list(),
        console     = list(),
        attach      = list(),
        trigger     = '0x41414141',
        shellcode   = '[ESP+8]',
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
