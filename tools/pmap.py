#!/bin/env python
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  http://tinyurl.com/nicolaseconomou

# Process memory map
# Copyright (c) 2009-2020, Mario Vilas
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

from winappdbg import Process, System, CrashDump, HexInput

def number(value):
    value = str(value)
    if len(value) % 3:
        value = ' ' * (3 - (len(value) % 3)) + value
    value = ','.join([value[i:i+3] for i in range(0, len(value), 3)])
    return value

def main():
    print "Process memory map"
    print "by Mario Vilas (mvilas at gmail.com)"
    print

    if len(sys.argv) < 2 or '-h' in sys.argv or '--help' in sys.argv:
        script = os.path.basename(sys.argv[0])
        print "Usage:"
        print "  %s <pid>..." % script
        print "  %s <process.exe>..." % script
        return

    s = System()
    s.request_debug_privileges()
    s.scan_processes()

    targets = set()
    for token in sys.argv[1:]:
        try:
            pid = HexInput.integer(token)
            if not s.has_process(pid):
                print "Process not found: %s" % token
                return
            targets.add(pid)
        except ValueError:
            pl = s.find_processes_by_filename(token)
            if not pl:
                print "Process not found: %s" % token
                return
            for p,n in pl:
                pid = p.get_pid()
                targets.add(pid)

    targets = list(targets)
    targets.sort()

    for pid in targets:
        process         = Process(pid)
        fileName        = process.get_filename()
        memoryMap       = process.get_memory_map()
        mappedFilenames = process.get_mapped_filenames()
        if fileName:
            print "Memory map for %d (%s):" % (pid, fileName)
        else:
            print "Memory map for %d:" % pid
        print
##        print CrashDump.dump_memory_map(memoryMap),
        print CrashDump.dump_memory_map(memoryMap, mappedFilenames)

        readable    = 0
        writeable   = 0
        executable  = 0
        private     = 0
        mapped      = 0
        image       = 0
        total       = 0
        for mbi in memoryMap:
            size = mbi.RegionSize
            if not mbi.is_free():
                total += size
            if mbi.is_readable():
                readable += size
            if mbi.is_writeable():
                writeable += size
            if mbi.is_executable():
                executable += size
            if mbi.is_private():
                private += size
            if mbi.is_mapped():
                mapped += size
            if mbi.is_image():
                image += size
        width = len(number(total))
        print ("  %%%ds bytes of readable memory" % width) % number(readable)
        print ("  %%%ds bytes of writeable memory" % width) % number(writeable)
        print ("  %%%ds bytes of executable memory" % width) % number(executable)
        print ("  %%%ds bytes of private memory" % width) % number(private)
        print ("  %%%ds bytes of mapped memory" % width) % number(mapped)
        print ("  %%%ds bytes of image memory" % width) % number(image)
        print ("  %%%ds bytes of total memory" % width) % number(total)
        print

if __name__ == '__main__':
    try:
        import psyco
        psyco.bind(main)
    except ImportError:
        pass
    main()
