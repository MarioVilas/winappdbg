#!/usr/bin/python3
# -*- coding: utf-8 -*-

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

import sys

from winappdbg import win32
from winappdbg.process import Process

# Get the process ID and output filename from the command line.
if len(sys.argv) < 2:
    print("Usage: %s <process_id> [output_file] [dump_type]" % sys.argv[0])
    print()
    print("  process_id  : Process ID to dump")
    print("  output_file : Output minidump file (default: minidump.dmp)")
    print("  dump_type   : Dump type flags (default: MiniDumpNormal)")
    print()
    print("Example dump types:")
    print("  MiniDumpNormal              - Basic information only")
    print("  MiniDumpWithFullMemory      - Include all accessible memory")
    print("  MiniDumpWithHandleData      - Include handle information")
    print("  MiniDumpWithThreadInfo      - Include thread information")
    print("  MiniDumpWithDataSegs        - Include data segments")
    print()
    print("Multiple flags can be combined with | (OR operator).")
    print("Example: MiniDumpWithFullMemory | MiniDumpWithHandleData")
    sys.exit(1)

pid = int(sys.argv[1])
output_file = sys.argv[2] if len(sys.argv) > 2 else "minidump.dmp"

# Parse dump type if provided
if len(sys.argv) > 3:
    # Allow user to specify flags like: MiniDumpWithFullMemory | MiniDumpWithHandleData
    dump_type_str = sys.argv[3]
    # Evaluate in a namespace with win32 constants
    dump_type = eval(dump_type_str, {"__builtins__": {}}, vars(win32))
else:
    dump_type = win32.MiniDumpNormal

try:
    # Create a Process object for the target process.
    process = Process(pid)

    # Generate the minidump file.
    print("Generating minidump for process %d..." % pid)
    print("Output file: %s" % output_file)
    print("Dump type: 0x%08X" % dump_type)

    process.generate_minidump(output_file, DumpType=dump_type)

    print("Minidump generated successfully!")

except WindowsError as e:
    print("Error: %s" % e)
    sys.exit(1)
except Exception as e:
    print("Unexpected error: %s" % e)
    import traceback

    traceback.print_exc()
    sys.exit(1)

