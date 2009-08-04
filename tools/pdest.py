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
from winappdbg import Debug, EventHandler, System, Process
from winappdbg import HexInput, HexDump, CrashDump

#------------------------------------------------------------------------------

class MemorySnapshot( object ):

    def __init__(self, process):
        super(MemorySnapshot, self).__init__()
        self.process = process
        self.__map   = list()
        self.__data  = dict()

    def get_process(self):
        return self.process

    def get_pid(self):
        return self.get_process().get_pid()

    def filter(self, mbi):
        return  mbi.State ==  win32.MEM_COMMIT and \
            not mbi.Protect & win32.PAGE_GUARD

    def scan(self):
        process = self.get_process()
        process.suspend()
        try:
            memory_map  = process.get_memory_map()
            data        = dict()
            for mbi in memory_map:
                if self.filter(mbi):
                    address       = mbi.BaseAddress
                    size          = mbi.RegionSize
                    data[address] = process.read(address, size)
            self.__map  = memory_map
            self.__data = data
        finally:
            process.resume()

    # XXX TODO
    # This method should check if the memory map hasn't changed
    # instead of assuming so.
    def restore(self):
        process = self.get_process()
        process.suspend()
        try:
            for address, data in self.__data.iteritems():
                process.write(address, data)
        finally:
            process.resume()

class WriteableMemorySnapshot( MemorySnapshot ):

    def filter(self, mbi):
        Protect = mbi.Protect
        return mbi.State == win32.MEM_COMMIT and \
            not Protect & win32.PAGE_GUARD and \
            (
            Protect & win32.PAGE_EXECUTE_READWRITE  or \
            Protect & win32.PAGE_EXECUTE_WRITECOPY  or \
            Protect & win32.PAGE_READWRITE          or \
            Protect & win32.PAGE_WRITECOPY
            )

#------------------------------------------------------------------------------

class ThreadContextSnapshot( object ):

    def __init__(self, thread):
        super(ThreadContextSnapshot, self).__init__()
        self.thread    = thread
        self.__context = dict()

    def get_thread(self):
        return self.thread

    def get_tid(self):
        return self.get_thread().get_tid()

    def scan(self):
        self.__context = self.get_thread().get_context()

    def restore(self):
        self.get_thread().set_context(self.__context)

#------------------------------------------------------------------------------

class BruteforceSnapshot( object ):

    MAX_INSTRUCTIONS = 10

    def __init__(self, event):
        super(BruteforceSnapshot, self).__init__()
        self.__memory    = WriteableMemorySnapshot(event.get_process())
        self.__registers = ThreadContextSnapshot(event.get_thread())
        self.__count     = 0

    def get_process(self):
        return self.__memory.get_process()

    def get_pid(self):
        return self.get_process().get_pid()

    def get_thread(self):
        return self.__registers.get_thread()

    def get_tid(self):
        return self.get_thread().get_tid()

    def begin(self):
        self.get_process().suspend()
        self.scan()
        self.get_thread().resume()

    def scan(self):
        self.__registers.scan()
        self.__memory.scan()

    def restore(self):
        self.__registers.restore()
        self.__memory.restore()

    def stop(self):
        self.restore()
        self.get_thread().suspend()
        self.get_process().resume()

    def try_address(self, address):
        self.__count = 0
        self.restore()
        self.get_thread().set_pc(address)

    def single_step(self, event):
        self.__count += 1
        if self.__count > self.MAX_INSTRUCTIONS:


class ReturnAddressBruteforce( EventHandler ):

    def __init__(self, options):
        super(ReturnAddressBruteforce, self).__init__()
        self.__options  = options
        self.__memory   = dict()
        self.__context  = dict()
        self.__trigger  = dict()

    def create_process(self, event):
        print event.get_event_name()            # XXX DEBUG
        self.__trap_trigger(event)

    def create_thread(self, event):
        print event.get_event_name()            # XXX DEBUG
        self.__trap_trigger(event)

    def single_step(self, event):
        print event.get_exception_description() # XXX DEBUG
        if event.debug.is_tracing( event.get_tid() ):
            self.__search(event)

    def __trap_trigger(self, event):
        print "trap"
        debug   = event.debug
        process = event.get_process()
        address = process.resolve_label(self.__options.trigger)

        print "address", hex(address)

        tid     = event.get_tid()
        print "tid", tid

##        for tid in process.iter_thread_ids():
##            print "tid", tid
##            debug.define_hardware_breakpoint(tid, address,
##                                             debug.BP_BREAK_ON_EXECUTION,
##                                             debug.BP_WATCH_BYTE,
##                                             True, self.__hit_trigger)
##            debug.enable_one_shot_hardware_breakpoint(tid, address)

        debug.stalk_at(event.get_pid(), address, self.__hit_trigger)

    def __hit_trigger(self, event):
        print "hit"
        pid     = event.get_pid()
        tid     = event.get_tid()
        print "tid", tid
        process = event.get_process()
        thread  = event.get_thread()
        pc      = thread.get_pc()
        memory  = WriteableMemorySnapshot(process)
        memory.scan()
        process.suspend()
        event.debug.start_tracing(tid)
        self.__memory[pid]  = memory
        self.__trigger[pid] = pc
        thread.resume()

    def __restore(self, event):
        pid     = event.get_pid()
        tid     = event.get_tid()
        process = event.get_process()
        thread  = event.get_thread()
        try:
            self.__memory[pid].restore()
            thread.set_pc( self.__trigger[pid] )
        except RuntimeError:
            print "error restoring!"
            process.kill()
        del self.__memory[pid]

    def __search(self, event):
        print "searching"
        print "...NOT!"
        event.get_process().kill()

#------------------------------------------------------------------------------

def main( argv ):

    # Parse the command line arguments
    options = parse_cmdline(argv)

    # Create the event handler object
    eventHandler = ReturnAddressBruteforce(options)

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
                  help="don't automatically detach from debugees on exit")
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
