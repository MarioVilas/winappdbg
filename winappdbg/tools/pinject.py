#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  https://www.linkedin.com/in/nicolas-alejandro-economou-51468743/

# Process DLL injector
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

import os
import sys

from winappdbg.process import Process
from winappdbg.system import System
from winappdbg.textio import HexInput


def main():
    print("Process DLL injector")
    print("by Mario Vilas (mvilas at gmail.com)")
    print()

    if len(sys.argv) != 3:
        script = os.path.basename(sys.argv[0])
        print("Injects a DLL into a running process.")
        print("  %s <pid> <library.dll>" % script)
        print("  %s <process.exe> <library.dll>" % script)
        return 1

    System.request_debug_privileges()

    try:
        pid = HexInput.integer(sys.argv[1])
    except Exception:
        s = System()
        s.scan_processes()
        pl = s.find_processes_by_filename(sys.argv[1])
        if not pl:
            print("Process not found: %s" % sys.argv[1])
            return 1
        if len(pl) > 1:
            print("Multiple processes found for %s" % sys.argv[1])
            for p, n in pl:
                print("\t%12d: %s" % (p.get_pid(), n))
            return 1
        pid = pl[0][0].get_pid()
    print("Using PID %d (0x%x)" % (pid, pid))

    dll = sys.argv[2]
    print("Using DLL %s" % dll)

    try:
        p = Process(pid)
        b = p.get_bits()
        if b != System.bits:
            print(
                "Cannot inject into a %d bit process from a %d bit Python VM!"
                % (b, System.bits)
            )
            return 1
        p.scan_modules()
        p.inject_dll(dll)
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
