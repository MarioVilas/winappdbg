#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2012, Mario Vilas
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

import os
import sys
import zlib
import winappdbg
from winappdbg import win32

try:
    import sqlite3 as sqlite
except ImportError:
    from pysqlite2 import dbapi2 as sqlite

# Create a snaphot of running processes
system = winappdbg.System()
system.request_debug_privileges()
system.scan_processes()

# Get all processes that match the requested filenames
for filename in sys.argv[1:]:
    print "Looking for: %s" % filename
    for process, pathname in system.find_processes_by_filename(filename):
        pid = process.get_pid()
        print "Dumping memory for process ID %d" % pid

        # Parse the database filename
        dbfile   = '%d.db' % pid
        if os.path.exists(dbfile):
            counter = 1
            while 1:
                dbfile = '%d_%.3d.db' % (pid, counter)
                if not os.path.exists(dbfile):
                    break
                counter += 1
            del counter
        print "Creating database %s" % dbfile

        # Connect to the database and get a cursor
        database = sqlite.connect(dbfile)
        cursor   = database.cursor()

        # Create the table for the memory map
        cursor.execute("""
            CREATE TABLE MemoryMap (
                Address INTEGER PRIMARY KEY,
                Size    INTEGER,
                State   STRING,
                Access  STRING,
                Type    STRING,
                File    STRING,
                Data    BINARY
            )
        """)

        # Get a memory map of the process
        memoryMap       = process.get_memory_map()
        mappedFilenames = process.get_mapped_filenames(memoryMap)

        # For each memory block in the map...
        for mbi in memoryMap:

            # Address and size of memory block
            BaseAddress = mbi.BaseAddress
            RegionSize  = mbi.RegionSize

            # State (free or allocated)
            if   mbi.State == win32.MEM_RESERVE:
                State   = "Reserved"
            elif mbi.State == win32.MEM_COMMIT:
                State   = "Commited"
            elif mbi.State == win32.MEM_FREE:
                State   = "Free"
            else:
                State   = "Unknown"

            # Page protection bits (R/W/X/G)
            if mbi.State != win32.MEM_COMMIT:
                Protect = ""
            else:
                if   mbi.Protect & win32.PAGE_NOACCESS:
                    Protect = "--- "
                elif mbi.Protect & win32.PAGE_READONLY:
                    Protect = "R-- "
                elif mbi.Protect & win32.PAGE_READWRITE:
                    Protect = "RW- "
                elif mbi.Protect & win32.PAGE_WRITECOPY:
                    Protect = "RC- "
                elif mbi.Protect & win32.PAGE_EXECUTE:
                    Protect = "--X "
                elif mbi.Protect & win32.PAGE_EXECUTE_READ:
                    Protect = "R-X "
                elif mbi.Protect & win32.PAGE_EXECUTE_READWRITE:
                    Protect = "RWX "
                elif mbi.Protect & win32.PAGE_EXECUTE_WRITECOPY:
                    Protect = "RCX "
                else:
                    Protect = "??? "
                if   mbi.Protect & win32.PAGE_GUARD:
                    Protect += "G"
                else:
                    Protect += "-"
                if   mbi.Protect & win32.PAGE_NOCACHE:
                    Protect += "N"
                else:
                    Protect += "-"
                if   mbi.Protect & win32.PAGE_WRITECOMBINE:
                    Protect += "W"
                else:
                    Protect += "-"

            # Type (file mapping, executable image, or private memory)
            if   mbi.Type == win32.MEM_IMAGE:
                Type    = "Image"
            elif mbi.Type == win32.MEM_MAPPED:
                Type    = "Mapped"
            elif mbi.Type == win32.MEM_PRIVATE:
                Type    = "Private"
            elif mbi.Type == 0:
                Type    = ""
            else:
                Type    = "Unknown"

            # Mapped file name, if any
            FileName = mappedFilenames.get(BaseAddress, None)

            # Read the data contained in the memory block, if any
            Data = None
            if mbi.has_content():
                print 'Reading %s-%s' % (
                    winappdbg.HexDump.address(BaseAddress),
                    winappdbg.HexDump.address(BaseAddress + RegionSize)
                )
                Data = process.read(BaseAddress, RegionSize)
                Data = zlib.compress(Data, zlib.Z_BEST_COMPRESSION)
                Data = sqlite.Binary(Data)

            # Output a row in the table
            cursor.execute(
                'INSERT INTO MemoryMap VALUES (?, ?, ?, ?, ?, ?, ?)',
                (BaseAddress, RegionSize, State, Protect, Type, FileName, Data)
            )

        # Commit the changes, close the cursor and the database
        database.commit()
        cursor.close()
        database.close()
        print "Ok."
print "Done."
