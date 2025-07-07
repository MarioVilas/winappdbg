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

from winappdbg.win32 import sizeof, SIZE_T, DWORD, EnumDeviceDrivers, GetDeviceDriverBaseName, GetDeviceDriverFileName

def print_drivers( fFullPath = False ):

    # Determine if we have 32 bit or 64 bit pointers.
    if sizeof(SIZE_T) == sizeof(DWORD):
        fmt = "%.08x\t%s"
        hdr = "%-8s\t%s"
    else:
        fmt = "%.016x\t%s"
        hdr = "%-16s\t%s"

    # Get the list of loaded device drivers.
    ImageBaseList = EnumDeviceDrivers()

    # Filter out None values (happens when SeDebugPrivilege is not enabled)
    ValidDrivers = [ImageBase for ImageBase in ImageBaseList if ImageBase is not None]

    print("Total entries returned: %d" % len(ImageBaseList))
    print("Valid device drivers found: %d" % len(ValidDrivers))

    if len(ValidDrivers) == 0 and len(ImageBaseList) > 0:
        print("WARNING: EnumDeviceDrivers returned NULL addresses.")
        print("This typically means SeDebugPrivilege is not enabled.")
        print("Try running this script as Administrator.")
        return

    if len(ValidDrivers) == 0:
        print("No device drivers found.")
        return

    print()
    print(hdr % ("Image base", "File name"))

    # For each valid device driver...
    for ImageBase in ValidDrivers:

        # Get the device driver filename.
        if fFullPath:
            DriverName = GetDeviceDriverFileName(ImageBase)
        else:
            DriverName = GetDeviceDriverBaseName(ImageBase)

        # Print the device driver image base and filename.
        print(fmt % (ImageBase, DriverName))

# When invoked from the command line,
# -f means show full pathnames instead of base filenames.
if __name__ == "__main__":
    import sys
    fFullPath = '-f' in sys.argv[1:]
    print_drivers( fFullPath )
