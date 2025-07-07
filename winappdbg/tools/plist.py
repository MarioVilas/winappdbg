#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  http://tinyurl.com/nicolaseconomou

# Process enumerator
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

# TODO
# Show more info on processes, for example the user that spawned them, or if
# they're being debugged or not.

# TODO
# Show threads in each process (optionally).

# TODO
# Get the names of the services running in each process.

# TODO
# Option to show the process tree instead of a list. (Maybe this should go to
# another tool instead, called "ptree.py").

# TODO
# How about showing some colors?
# It'd be useful when using a search string, to highlight the matching parts.
# Also to show processes run by SYSTEM or other users with different colors.
# Can be done with colorama/termcolor or raw win32 api if it's easy enough.

import optparse
import sys

from winappdbg.system import System
from winappdbg.textio import Table
from winappdbg.util import PathOperations


def parse_cmdline(argv):
    "Parse the command line options."
    parser = optparse.OptionParser()
    parser.add_option(
        "--format",
        action="store",
        default="auto",
        choices=("auto", "wide", "long"),
        help="display format [default: auto]",
    )
    parser.add_option(
        "-f",
        "--full-path",
        action="store_true",
        default=False,
        help="show full pathnames",
    )
    parser.add_option(
        "-w",
        "--windows",
        action="store_true",
        default=False,
        help="show window captions for each process",
    )
    parser.add_option(
        "-d",
        "--services",
        action="store_true",
        default=False,
        help="show services running on each process",
    )
    parser.add_option("-s", "--search", metavar="STRING", help="optional search string")
    (options, argv) = parser.parse_args(argv)
    if len(argv) > 1:
        parser.error("unexpected parameter: %s" % argv[1])
    return (options, argv)


def main():
    "Main function."

    # print(the banner.)
    print("Process enumerator")
    print("by Mario Vilas (mvilas at gmail.com)")
    print()

    # Parse the command line options.
    argv = sys.argv
    (options, argv) = parse_cmdline(argv)
    showFilenameOnly = not options.full_path
    searchString = options.search

    # Windows filenames are case insensitive.
    if searchString:
        searchString = searchString.lower()

    # Take a snapshot of the running processes.
    s = System()
    s.request_debug_privileges()
    try:
        s.scan_processes()
        if not showFilenameOnly:
            s.scan_process_filenames()
    except WindowsError:
        s.scan_processes_fast()
    pid_list = s.get_process_ids()
    if not pid_list:
        print("Unknown error enumerating processes!")
        return
    pid_list = sorted(pid_list)

    # Get the filename of each process.
    filenames = dict()
    for pid in pid_list:
        p = s.get_process(pid)
        fileName = p.get_filename()

        # Special process IDs.
        # PID 0: System Idle Process. Also has a special meaning to the
        #        toolhelp APIs (current process).
        # PID 4: System Integrity Group. See this forum post for more info:
        #        http://tinyurl.com/ycza8jo
        #        (points to social.technet.microsoft.com)
        #        Only on XP and above
        # PID 8: System (?) only in Windows 2000 and below AFAIK.
        #        It's probably the same as PID 4 in XP and above.
        if pid == 0:
            fileName = "[System Idle Process]"
        elif pid == 4:
            fileName = "[System Integrity Group]"
        elif pid == 8:
            fileName = "[System]"

        # Filename not available.
        elif not fileName:
            fileName = ""

        # Get the process pathname instead, if requested.
        elif showFilenameOnly:
            fileName = PathOperations.pathname_to_filename(fileName)

        # Filter the output with the search string.
        if searchString and searchString not in fileName.lower():
            continue

        # Remember the filename.
        if isinstance(fileName, bytes):
            fileName = fileName.decode()
        filenames[pid] = fileName

    # Get the window captions if requested.
    # TODO: show window handles too if possible
    captions = dict()
    if options.windows:
        for w in s.get_windows():
            try:
                pid = w.get_pid()
                text = w.get_text()
                if text != "":
                    text = text.decode("utf-8", "replace")
            except WindowsError:
                continue
            try:
                captions[pid].add(text)
            except KeyError:
                capset = set()
                capset.add(text)
                captions[pid] = capset

    # Get the services if requested.
    services = dict()
    if options.services:
        try:
            for descriptor in s.get_services():
                try:
                    services[descriptor.ProcessId].add(descriptor.ServiceName)
                except KeyError:
                    srvset = set()
                    srvset.add(descriptor.ServiceName)
                    services[descriptor.ProcessId] = srvset
        except WindowsError as e:
            print("Error getting the list of services: %s" % str(e))
            return

    if options.format == "auto":
        if options.windows or options.services:
            options.format = "long"
    if options.format != "long":
        headers = [" PID", "Filename"]
        if options.windows:
            headers.append("Windows")
        if options.services:
            headers.append("Services")
        table = Table()
        table.addRow(*headers)
        for pid in pid_list:
            if pid in filenames:
                fileName = filenames[pid]
                caplist = sorted(captions.get(pid, set()))
                srvlist = sorted(services.get(pid, set()))
                if options.windows and options.services:
                    if len(caplist) < len(srvlist):
                        caplist.extend([""] * (len(srvlist) - len(caplist)))
                    elif len(srvlist) < len(caplist):
                        srvlist.extend([""] * (len(caplist) - len(srvlist)))
                    if len(caplist):
                        table.addRow(" %d" % pid, fileName, caplist[0], srvlist[0])
                        for i in range(1, len(caplist)):
                            table.addRow("", "", caplist[i], srvlist[i])
                    else:
                        table.addRow(" %d" % pid, fileName, "", "")
                elif options.windows:
                    if len(caplist):
                        table.addRow(" %d" % pid, fileName, caplist[0])
                        for i in range(1, len(caplist)):
                            table.addRow("", "", caplist[i])
                    else:
                        table.addRow(" %d" % pid, fileName, "")
                elif options.services:
                    if len(srvlist):
                        table.addRow(" %d" % pid, fileName, srvlist[0])
                        for i in range(1, len(srvlist)):
                            table.addRow("", "", srvlist[i])
                    else:
                        table.addRow(" %d" % pid, fileName, "")
                else:
                    table.addRow(" %d" % pid, fileName)
        table.justify(0, 1)
        if options.format == "auto" and table.getWidth() >= 80:
            options.format = "long"
        else:
            table.show()
    if options.format == "long":
        # If it doesn't fit, build a new table of only two rows. The first row
        # contains the headers and the second row the data. Insert an empty row
        # between each process.
        need_empty_row = False
        table = Table()
        for pid in pid_list:
            if pid in filenames:
                if need_empty_row:
                    table.addRow()
                else:
                    need_empty_row = True
                table.addRow("PID:", pid)
                fileName = filenames[pid]
                if fileName:
                    table.addRow("Filename:", fileName)
                caplist = sorted(captions.get(pid, set()))
                if caplist:
                    caption = caplist.pop(0)
                    table.addRow("Windows:", caption)
                    for caption in caplist:
                        table.addRow("", caption)
                srvlist = sorted(services.get(pid, set()))
                if srvlist:
                    srvname = srvlist.pop(0)
                    table.addRow("Services:", srvname)
                    for srvname in srvlist:
                        table.addRow("", srvname)
        table.justify(0, 1)
        table.show()


if __name__ == "__main__":
    main()
