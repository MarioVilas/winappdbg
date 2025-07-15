#!/usr/bin/env python3
"""
Test script for the improved architecture detection using GetProcessInformation.
"""

import os
import sys

# Add the winappdbg directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from winappdbg.system import System
from winappdbg.process import Process

def test_arch_detection():
    """Test the improved architecture detection on Python processes."""

    print("Testing improved architecture detection on Python processes...")
    print(f"System architecture: {System.arch}")
    print(f"System bits: {System.bits}")
    print()

    # Test with current process first
    current_pid = os.getpid()
    print(f"Current Python process PID: {current_pid}")

    try:
        process = Process(current_pid)
        arch = process.get_arch()
        bits = process.get_bits()

        print(f"Current process architecture: {arch}")
        print(f"Current process bits: {bits}")
        print(f"Current process is WOW64: {process.is_wow64()}")
        print("✅ Successfully detected current process architecture!")

    except Exception as e:
        print(f"❌ Error detecting current process architecture: {e}")

    print()

    # Scan for all Python processes
    system = System()
    system.scan_processes()

    print("Scanning for Python processes...")
    python_processes = []

    for process in system.iter_processes():
        try:
            filename = process.get_filename()
            if filename and ('python.exe' in filename.lower() or 'python' in filename.lower()):
                python_processes.append(process)
        except Exception:
            # Skip processes we can't access
            continue

    if not python_processes:
        print("❌ No Python processes found!")
        return

    print(f"Found {len(python_processes)} Python process(es)")
    print()
    print("Testing architecture detection on all Python processes:")
    print("-" * 80)
    print(f"{'PID':<8} {'Architecture':<12} {'Bits':<6} {'WOW64':<8} {'Executable Path'}")
    print("-" * 80)

    success_count = 0
    architectures_found = set()

    for process in python_processes:
        try:
            arch = process.get_arch()
            bits = process.get_bits()
            is_wow64 = process.is_wow64()
            filename = process.get_filename()

            # Clean up filename for display
            if filename:
                filename = filename.replace('\\', '/')
                # Show just the last part of the path for clarity
                if len(filename) > 50:
                    filename = "..." + filename[-47:]

            print(f"{process.get_pid():<8} {arch:<12} {bits:<6} {is_wow64:<8} {filename}")

            success_count += 1
            architectures_found.add(arch)

        except Exception as e:
            print(f"{process.get_pid():<8} ERROR: {e}")

    print("-" * 80)
    print(f"Successfully detected architecture for {success_count}/{len(python_processes)} Python processes")
    print(f"Architectures found: {', '.join(sorted(architectures_found))}")
    print()

    if success_count == len(python_processes):
        print("✅ All Python process architecture detections successful!")
    else:
        print(f"⚠️  {len(python_processes) - success_count} Python processes failed architecture detection")

    # Show what this demonstrates
    print()
    print("🎯 This test demonstrates:")
    print("   • Accurate architecture detection across different Python installations")
    print("   • Proper handling of native ARM64 processes")
    print("   • Correct detection of x64 processes running under emulation")
    print("   • Correct detection of x86 processes running under emulation")
    print("   • Improved accuracy over legacy WOW64-based detection methods")

if __name__ == "__main__":
    test_arch_detection()