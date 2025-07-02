#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Service tool
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

from winappdbg.system import System
from winappdbg.util import PathOperations
from winappdbg.textio import Table
from winappdbg import win32

import optparse, time

def main():
    'Main function.'

    # print(the banner.)
    print("Service tool")
    print("by Mario Vilas (mvilas at gmail.com)")
    print()

    # Parse the command line options.
    parser = optparse.OptionParser()
    parser.add_option("-w", "--wide", action="store_true", default=False,
                      help="show list of services in wide format")
    (options, argv) = parser.parse_args(sys.argv)

    # Parse the command line options.
    if not argv:
        command = 'list'
    else:
        command = argv[0].strip().lower()
    if command not in ('list', 'start', 'stop', 'pause', 'resume'):
        parser.error("unknown command: %s" % command)
    try:
        target = argv[1].strip().lower()
    except IndexError:
        target = None
        if command != 'list':
            parser.error("missing argument for the %s command" % command)
    if command == 'start':
        target_args = argv[2:]
    elif len(argv) > 2:
        parser.error("extra arguments")

    # Run the command.
    if   command == 'list':
        show(target, options.wide)
    elif command == 'start':
        start(target, target_args)
    elif command == 'stop':
        stop(target)
    elif command == 'pause':
        pause(target)
    elif command == 'resume':
        resume(target)
    else:
        parser.error("internal error")

def show(search = None, wide = True):
    'show a table with the list of services'

    # Take a snapshot of the running processes.
    s = System()
    s.request_debug_privileges()
    try:
        s.scan_processes()
        s.scan_process_filenames()
    except WindowsError:
        s.scan_processes_fast()
    pid_list = sorted(s.get_process_ids())
    if not pid_list:
        print("Unknown error enumerating processes!")
        return

    # Get the filename of each process.
    filenames = dict()
    for pid in pid_list:
        p = s.get_process(pid)

        # Special process IDs.
        # PID 0: System Idle Process. Also has a special meaning to the
        #        toolhelp APIs (current process).
        # PID 4: System Integrity Group. See this forum post for more info:
        #        http://tinyurl.com/ycza8jo
        #        (points to social.technet.microsoft.com)
        #        Only on XP and above
        # PID 8: System (?) only in Windows 2000 and below AFAIK.
        #        It's probably the same as PID 4 in XP and above.
        if pid in (0, 4, 8):
            fileName = ""

        # Get the filename for all other processes.
        else:
            fileName = p.get_filename()
            if fileName:
                fileName = PathOperations.pathname_to_filename(fileName)
            else:
                fileName = ""

        # Remember the filename.
        filenames[pid] = fileName

    # Make the search string lowercase if given.
    if search is not None:
        search = search.lower()

    # Get the list of services.
    try:
        services = System.get_services()
    except WindowsError as e:
        print(str(e))
        return

    # Convert the list of services to a list of rows.
    data = []
    for descriptor in services:

        # Filter out services that don't match the search string if given.
        if search is not None and \
            not search in descriptor.ServiceName.lower() and \
            not search in descriptor.DisplayName.lower():
                continue

        # Status.
        if   descriptor.CurrentState == win32.SERVICE_CONTINUE_PENDING:
            status = "Resuming..."
        elif descriptor.CurrentState == win32.SERVICE_PAUSE_PENDING:
            status = "Pausing..."
        elif descriptor.CurrentState == win32.SERVICE_PAUSED:
            status = "Paused"
        elif descriptor.CurrentState == win32.SERVICE_RUNNING:
            status = "Running"
        elif descriptor.CurrentState == win32.SERVICE_START_PENDING:
            status = "Starting..."
        elif descriptor.CurrentState == win32.SERVICE_STOP_PENDING:
            status = "Stopping..."
        elif descriptor.CurrentState == win32.SERVICE_STOPPED:
            status = "Stopped"

        # Type.
        if   descriptor.ServiceType & win32.SERVICE_INTERACTIVE_PROCESS:
            type = 'Win32 GUI'
        elif descriptor.ServiceType & win32.SERVICE_WIN32:
            type = 'Win32'
        elif descriptor.ServiceType & win32.SERVICE_DRIVER:
            type = 'Driver'
        else:
            type = 'Unknown'

        # Process ID.
        try:
            pid = descriptor.ProcessId
            if pid:
                pidStr = str(pid)
            else:
                pidStr = ""
        except AttributeError:
            pid = None
            pidStr = ""

        # Filename.
        fileName = filenames.get(pid, "")

        # Append the row.
        data.append( (descriptor.ServiceName, descriptor.DisplayName,
                      status, type, pidStr, fileName) )

    # Sort the rows.
    data = sorted(data)

    # Build the table and print(it.)
    if wide:
        headers = ("Service", "Display name", "Status", "Type", "PID", "Path")
        table = Table()
        table.addRow(*headers)
        separator = ['-' * len(x) for x in headers]
        table.addRow(*separator)
        for row in data:
            table.addRow(*row)
        table.show()
    else:
        need_empty_line = False
        for (name, disp, status, type, pidStr, path) in data:
            if need_empty_line:
                print()
            else:
                need_empty_line = True
            print("Service name:   %s" % name)
            if disp:
                print("Display name:   %s" % disp)
            print("Current status: %s" % status)
            print("Service type:   %s" % type)
            if pidStr:
                pid = int(pidStr)
                print("Process ID:     %d (0x%x)" % (pid, pid))
            if path:
                print("Host filename:  %s" % path)

def copypasta(action, params, wait_state, doing_verb, done_verb):
    'common code in a lot of methods here :)'
    try:
        target = params[0]

        # Do the requested action.
        status = System.get_service(target)
        try:
            name = System.get_service_display_name(target)
        except WindowsError:
            name = target
        print("%s service \"%s\"..." % (doing_verb, name))
        action(*params)

        # Wait for it to finish.
        timeout = 20
        status = System.get_service(target)
        while status.CurrentState == wait_state:
            timeout -= 1
            if timeout <= 0:
                print("Error: timed out.")
                return
            time.sleep(0.5)
            status = System.get_service(target)

        # Done.
        print("Service %s successfully." % done_verb)

    # On error show a message and quit.
    except WindowsError as e:
        print(str(e))
        return

def start(target, target_args):
    'start a service'
    copypasta(System.start_service, (target, target_args),
              win32.SERVICE_START_PENDING, "Starting", "started")

def stop(target):
    'stop a service'
    copypasta(System.stop_service, (target,),
              win32.SERVICE_STOP_PENDING, "Stopping", "stopped")

def pause(target):
    'resume a service'
    copypasta(System.resume_service, (target,),
              win32.SERVICE_PAUSE_PENDING, "Pausing", "paused")

def resume(target):
    'resume a service'
    copypasta(System.resume_service, (target,),
              win32.SERVICE_CONTINUE_PENDING, "Resuming", "resumed")

if __name__ == '__main__':
    import sys
    main(sys.argv[1:])
