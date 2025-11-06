#!/usr/bin/env python
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
from winappdbg.system import System
from winappdbg import appmodel


def main():
    # Create a system snapshot
    system = System()
    system.scan_processes()

    # Iterate through all processes
    for process in system.iter_processes():
        try:
            # Try to get the package full name
            package_full_name = process.get_package_full_name()

            # Only process packaged apps
            if not package_full_name:
                continue

            # Parse the package full name to extract components
            info = appmodel.parse_package_full_name(package_full_name)

            if not info:
                # Couldn't parse, just show the raw name
                print("%d\t%s" % (process.get_pid(), package_full_name))
                continue

            # Build the AUMID (assume App ID is "App")
            aumid = appmodel.build_aumid(info['package_family_name'], "App")

            # Print formatted information
            print("PID %d:" % process.get_pid())
            print("  Name:         %s" % info['name'])
            print("  Version:      %s" % info['version'])
            print("  Architecture: %s" % info['architecture'])
            print("  Family Name:  %s" % info['package_family_name'])
            print("  AUMID:        %s" % aumid)
            print()

        except Exception:
            # Skip processes we can't access
            pass


# When invoked from the command line,
# call the main() function.
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
