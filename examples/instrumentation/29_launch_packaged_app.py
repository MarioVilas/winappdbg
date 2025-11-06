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


def main(argv):
    # Check if comtypes is available
    if not appmodel.HAS_COMTYPES:
        print("Error: comtypes library is not installed")
        print("Install it with: pip install winappdbg[packaged_apps]")
        return 1

    # Check command line arguments
    if len(argv) < 2:
        print("Usage: %s <AUMID> [arguments]" % argv[0])
        print()
        print("AUMID format: PackageFamilyName!ApplicationId")
        print()
        print("Examples:")
        print("  %s Microsoft.WindowsCalculator_8wekyb3d8bbwe!App" % argv[0])
        print("  %s Microsoft.WindowsNotepad_8wekyb3d8bbwe!App" % argv[0])
        print()
        print("To find AUMIDs:")
        print("  Run example 28 to see running packaged apps and their AUMIDs")
        print("  Or use PowerShell: Get-StartApps")
        return 1

    # Get the AUMID from command line
    aumid = argv[1]

    # Get optional arguments
    arguments = " ".join(argv[2:]) if len(argv) > 2 else None

    # Launch the app
    print("Launching: %s" % aumid)
    if arguments:
        print("Arguments: %s" % arguments)

    try:
        system = System()
        process = system.start_packaged_app(aumid, arguments=arguments)

        print("Process ID: %d" % process.get_pid())

        # Try to get the package full name
        try:
            package_full_name = process.get_package_full_name()
            if package_full_name:
                print("Package: %s" % package_full_name)
        except Exception:
            pass

    except ImportError as e:
        print("Error: %s" % e)
        return 1
    except WindowsError as e:
        print("Failed to launch application: %s" % e)
        return 1

    return 0


# When invoked from the command line,
# call the main() function.
if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except KeyboardInterrupt:
        print()
        print("Interrupted by user")
