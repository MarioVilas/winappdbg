#!/bin/env python
# -*- coding: utf-8 -*-

# Acknowledgements:
#  Nicolas Economou, for his ptool suite on which this tool is inspired.
#  http://tinyurl.com/nicolaseconomou

# Process memory reader
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

import argparse
import sys

from winappdbg.system import System
from winappdbg.process import Process
from winappdbg.textio import HexDump


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Process string extractor by Mario Vilas (mvilas at gmail.com)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s notepad.exe
  %(prog)s 1234 --min-length 8 --encoding ascii
  %(prog)s chrome.exe -v --limit 100
        """,
    )

    parser.add_argument(
        "target", help="Process ID (PID) or process name to extract strings from"
    )

    parser.add_argument(
        "--min-length",
        "-n",
        type=int,
        default=4,
        metavar="N",
        help="Minimum string length in characters (default: 4)",
    )

    parser.add_argument(
        "--encoding",
        "-e",
        choices=["ascii", "unicode", "both"],
        default="both",
        help="Encoding type: ascii, unicode, or both (default: both)",
    )

    parser.add_argument(
        "--limit", "-l", type=int, metavar="N", help="Limit output to first N strings"
    )

    # Verbose/quiet mode
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Verbose output with headers and statistics",
    )
    output_group.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        default=True,
        help="Quiet output, only addresses and strings (default)",
    )

    args = parser.parse_args()

    # If --verbose is explicitly set, turn off quiet
    if args.verbose:
        args.quiet = False

    # Show banner in verbose mode
    if args.verbose:
        print("Process string extractor")
        print("by Mario Vilas (mvilas at gmail.com)")
        print()

    # Initialize system and request debug privileges
    system = System()
    system.request_debug_privileges()
    system.scan_processes()

    # Find the target process
    try:
        pid = int(args.target)
        if not system.has_process(pid):
            print(f"Error: Process with PID {pid} not found", file=sys.stderr)
            return 1
    except ValueError:
        # Target is a process name
        found = system.find_processes_by_filename(args.target)
        if not found:
            print(f"Error: Process '{args.target}' not found", file=sys.stderr)
            return 1
        if len(found) > 1:
            print(
                f"Error: Multiple processes found for '{args.target}'", file=sys.stderr
            )
            print("Please specify one of the following PIDs:", file=sys.stderr)
            for process, filename in found:
                print(f"  {process.get_pid()}: {filename}", file=sys.stderr)
            return 1
        pid = found[0][0].get_pid()
        if args.verbose:
            print(f"Found process '{args.target}' with PID {pid}")

    # Open the process
    try:
        process = Process(pid)
        process.get_handle()
    except WindowsError as e:
        print(f"Error: Cannot open process {pid}: {e}", file=sys.stderr)
        return 1

    # Show extraction info in verbose mode
    if args.verbose:
        print(f"\nExtracting strings from process {pid}...")
        print(f"  Minimum length: {args.min_length} characters")
        print(f"  Encoding: {args.encoding}")
        print(f"  Limit: {args.limit if args.limit else 'none'}")
        print("\n" + "=" * 80 + "\n")

    count = 0
    try:
        for address, string in process.strings(
            minLength=args.min_length, encoding=args.encoding
        ):
            # Print the address and string
            if args.quiet:
                # Quiet mode: minimal output like the old script
                print(f"{HexDump.address(address)}: {string!r}")
            else:
                # Verbose mode: full hex address with 0x prefix
                print(f"0x{address:016x}: {string!r}")

            count += 1

            # Check if we've reached the limit
            if args.limit and count >= args.limit:
                if args.verbose:
                    print(f"\n... (output limited to {args.limit} strings)")
                break

    except KeyboardInterrupt:
        if args.verbose:
            print("\n\nInterrupted by user", file=sys.stderr)
        return 130  # Standard exit code for SIGINT
    except Exception as e:
        print(f"\nError during string extraction: {e}", file=sys.stderr)
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1

    # Show statistics in verbose mode
    if args.verbose:
        print(f"\n{count} strings extracted.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
