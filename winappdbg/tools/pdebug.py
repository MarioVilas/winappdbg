#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Nicolas Economou, for his command line debugger on which this is inspired.
#  https://www.linkedin.com/in/nicolas-alejandro-economou-51468743/

# Command line debugger using WinAppDbg
# Copyright (c) 2009-2025, Mario Vilas
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

import optparse
import sys

import winappdbg
from winappdbg.debug import Debug
from winappdbg.interactive import ConsoleDebugger
from winappdbg.system import System


class PDebug(ConsoleDebugger):
    history_file = ".pdebug"  # backwards compatibility with WinAppDbg 1.4
    confirm_quit = True  # confirm before quitting

    # Override the help message.
    def do_quit(self, arg):
        """
        quit - detach from all processes and shut down the debugger
        q - detach from all processes and shut down the debugger
        """
        ConsoleDebugger.do_quit(self, arg)

    do_q = do_quit

    # ------------------------------------------------------------------------------
    # Run from the command line

    # Run the debugger.
    # This is the first method called.
    def run(self, argv):
        self.argv = list(argv)
        try:
            self.initialize()
            self.loop()
        finally:
            self.finalize()

    # Initialize the debugger.
    def initialize(self):
        self.print_banner()
        self.parse_cmdline()
        self.create_debugger()
        self.queue_initial_commands()
        self.load_history()

    ##        self.set_control_c_handler()

    # Clean up when closing the debugger.
    def finalize(self):
        ##        self.remove_control_c_handler()
        if hasattr(self, "options"):
            self.destroy_debugger(self.options.autodetach)
        self.save_history()

    # Instance a Debug object and start using it.
    def create_debugger(self):
        # Instance a debugger
        debug = Debug(self, bHostileCode=self.options.hostile)

        # Make sure the remote symbol store is set
        System.fix_symbol_store_path(remote=True, force=False)

        # Populate the snapshot of processes
        debug.system.scan()

        # Use this debugger
        self.start_using_debugger(debug)

    # print(the welcome banner.)
    def print_banner(self):
        print("WinAppDbg %s console debugger" % winappdbg.version)
        print("by Mario Vilas (mvilas at gmail.com)")
        print()

    # ------------------------------------------------------------------------------
    # Command line parsing

    # TODO
    # * add an option to show python tracebacks of all errors, disabled by default

    # Define the command line parser and parse the command line.
    def parse_cmdline(self):
        # Define the command line parser
        usage = (
            "\n"
            "\n"
            "  Just show the prompt:\n"
            "    %prog\n"
            "\n"
            "  Create a new process:\n"
            '    %prog [options] -c "console_target.exe optional parameters..."\n'
            '    %prog [options] -w "windowed_target.exe optional parameters..."\n'
            "\n"
            "  Attach to a running process (by filename):\n"
            '    %prog [options] -a "executable"\n'
            "\n"
            "  Attach to a running process (by ID):\n"
            "    %prog [options] -a pid"
        )
        self.parser = optparse.OptionParser(
            usage=usage,
            version=winappdbg.version,
        )
        commands = optparse.OptionGroup(self.parser, "Commands")
        commands.add_option(
            "-a",
            "--attach",
            action="append",
            type="string",
            metavar="PROCESS",
            help="Attach to a running process",
        )
        commands.add_option(
            "-w",
            "--windowed",
            action="callback",
            type="string",
            metavar="CMDLINE",
            callback=self.callback_execute_target,
            help="Create a new windowed process",
        )
        commands.add_option(
            "-c",
            "--console",
            action="callback",
            type="string",
            metavar="CMDLINE",
            callback=self.callback_execute_target,
            help="Create a new console process [default]",
        )
        self.parser.add_option_group(commands)
        debugging = optparse.OptionGroup(self.parser, "Debugging options")
        debugging.add_option(
            "--autodetach",
            action="store_true",
            help="automatically detach from debugees on exit [default]",
        )
        debugging.add_option(
            "--follow",
            action="store_true",
            help="automatically attach to child processes [default]",
        )
        debugging.add_option(
            "--trusted",
            action="store_false",
            dest="hostile",
            help="treat debugees as trusted code [default]",
        )
        debugging.add_option(
            "--dont-autodetach",
            action="store_false",
            dest="autodetach",
            help="don't automatically detach from debugees on exit",
        )
        debugging.add_option(
            "--dont-follow",
            action="store_false",
            dest="follow",
            help="don't automatically attach to child processes",
        )
        debugging.add_option(
            "--hostile", action="store_true", help="treat debugees as hostile code"
        )
        self.parser.add_option_group(debugging)

        # Set the default values
        self.parser.set_defaults(
            attach=[],
            console=[],
            windowed=[],
            autodetach=True,
            follow=True,
            hostile=False,
        )

        # Parse the command line
        (self.options, args) = self.parser.parse_args(self.argv)
        args = args[1:]
        if (
            not self.options.windowed
            and not self.options.console
            and not self.options.attach
        ):
            if args:
                self.options.console = [args]
        else:
            if args:
                self.parser.error(
                    "don't know what to do with extra parameters: %s" % args
                )

    # Callback to parse -c and -w command line switches
    @staticmethod
    def callback_execute_target(option, opt_str, value, parser):
        # Get the destination variable name.
        dest_name = option.dest
        if dest_name is None:
            dest_name = option.get_opt_string().replace("-", "")

        # Get the destination list to append.
        # Create a new list if needed.
        destination = getattr(parser.values, dest_name, None)
        if destination is None:
            destination = list()
            setattr(parser.values, dest_name, destination)

        # If a value is received from optparse, put it back in the list of
        # arguments to be consumed.
        #
        # From what I gather by examining the examples in the documentation this
        # wasn't even supposed to happen. (!)
        #
        # I suspect is happening because I had to force the argument type for the
        # command line switch definition as a workaround for another bug (the
        # metavariable wasn't being shown in the help message).
        #
        if value is not None:
            parser.rargs.insert(0, value)

        # Get the value from the command line arguments.
        value = []
        for arg in parser.rargs:
            # Stop on --foo like options but not on -- alone.
            if arg[:2] == "--" and len(arg) > 2:
                break

            # Stop on -a like options but not on - alone.
            if arg[:1] == "-" and len(arg) > 1:
                break

            value.append(arg)

        # Delete the command line arguments we consumed so they're not parsed again.
        del parser.rargs[: len(value)]

        # Append the value to the destination list.
        destination.append(value)

    # Queue the startup commands when running from command line.
    def queue_initial_commands(self):
        # Queue the attach commands, if needed
        if self.options.attach:
            cmd = "attach %s" % self.join_tokens(self.options.attach)
            self.cmdqueue.append(cmd)

        # Queue the windowed commands, if needed
        for argv in self.options.windowed:
            cmdline = System.argv_to_cmdline(argv)
            self.cmdqueue.append("windowed %s" % cmdline)

        # Queue the console commands, if needed
        for argv in self.options.console:
            cmdline = System.argv_to_cmdline(argv)
            self.cmdqueue.append("console %s" % cmdline)

        # Queue the continue command, if other commands were queued before
        if len(self.cmdqueue) > 0:
            self.cmdqueue.append("continue")


# ==============================================================================


def main():
    return PDebug().run(sys.argv)


if __name__ == "__main__":
    main()
