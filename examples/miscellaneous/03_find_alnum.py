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

# Note:
# This simple approach seems fast enough. But if there's ever a need to
# optimize this for 32 bits Windows this is how it could be done: since
# the system allocation granularity is 64k, it should be possible to
# precalculate the lower 16 bits of all possible alphanumeric addresses,
# then only test the higher 16 bits of the address for each memory region.

from struct import pack

from winappdbg.process import Process
from winappdbg.system import System
from winappdbg.textio import HexDump


# Iterator of alphanumeric executable addresses.
def iterate_alnum_jump_addresses(process):
    # Determine the size of a pointer for this process.
    if process.get_bits() == 32:
        fmt = "L"
    elif process.get_bits() == 64:
        fmt = "Q"
        print("Warning! 64 bit addresses are not likely to be alphanumeric!")
    else:
        raise NotImplementedError

    # Get an iterator for the target process memory.
    iterator = process.generate_memory_snapshot()

    # Iterate the memory regions of the target process.
    for mbi in iterator:
        # Discard non executable memory.
        if not mbi.is_executable():
            continue

        # Get the module that owns this memory region, if any.
        address = mbi.BaseAddress
        module = process.get_module_at_address(address)

        # Yield each alphanumeric address in this memory region.
        max_address = address + mbi.RegionSize
        while address < max_address:
            packed = pack(fmt, address)
            if packed.isalnum():
                yield address, packed, module
            address = address + 1


# Iterate and print alphanumeric executable addresses.
def print_alnum_jump_addresses(pid):
    # Request debug privileges so we can inspect the memory of services too.
    System.request_debug_privileges()

    # Suspend the process so there are no malloc's and free's while iterating.
    process = Process(pid)
    process.suspend()
    try:
        # For each executable alphanumeric address...
        for address, packed, module in iterate_alnum_jump_addresses(process):
            # Format the address for printing.
            numeric = HexDump.address(address, process.get_bits())
            ascii = repr(packed)

            # Format the module name for printing.
            if module:
                modname = module.get_name()
            else:
                modname = ""

            # Try to disassemble the code at this location.
            try:
                code = process.disassemble(address, 16)[0][2]
            except NotImplementedError:
                code = ""

            # Print it.
            print(numeric, ascii, modname, code)

    # Resume the process when we're done.
    # This is inside a "finally" block, so if the program is interrupted
    # for any reason we don't leave the process suspended.
    finally:
        process.resume()


# When invoked from the command line,
# the first argument is the process ID.
if __name__ == "__main__":
    from sys import argv

    pid = int(argv[1])
    try:
        print_alnum_jump_addresses(pid)
    except KeyboardInterrupt:
        print("Interrupted by the user.")
    except Exception:
        import traceback

        traceback.print_exc()
