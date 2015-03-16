#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2015, Mario Vilas
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

from winappdbg import System, Table
from winappdbg.win32 import PROCESS_DEP_ENABLE, \
                            PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION, \
                            ERROR_ACCESS_DENIED

# Prepare the table.
header = ( " PID ", "DEP ", "DEP-ATL ", "Permanent ", "Filename " )
separator = [ " " * len(x) for x in header ]
table = Table()
table.addRow( *header )
table.addRow( *separator )

# Request debug privileges.
System.request_debug_privileges()

# Scan for running processes.
system = System()
try:
    system.scan_processes()
    #system.scan_process_filenames()
except WindowsError:
    system.scan_processes_fast()

# For each running process...
for process in system.iter_processes():
    try:

        # Get the process ID.
        pid = process.get_pid()

        # Skip "special" process IDs.
        if pid in (0, 4, 8):
            continue

        # Skip 64 bit processes.
        if process.get_bits() != 32:
            continue

        # Get the DEP policy flags.
        flags, permanent = process.get_dep_policy()

        # Determine if DEP is enabled.
        if flags & PROCESS_DEP_ENABLE:
            dep = " X"
        else:
            dep = ""

        # Determine if DEP-ATL thunk emulation is enabled.
        if flags & PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION:
            atl = ""
        else:
            atl = "   X"

        # Determine if the current DEP flag is permanent.
        if permanent:
            perm = "    X"
        else:
            perm = ""

    # Skip processes we don't have permission to access.
    except WindowsError, e:
        if e.winerror == ERROR_ACCESS_DENIED:
            continue
        raise

    # Get the filename.
    filename = process.get_filename()

    # Add the process to the table.
    table.addRow( pid, dep, atl, perm, filename )

# Print the table.
table.show()
