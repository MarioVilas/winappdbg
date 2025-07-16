#!/usr/bin/env python3
"""
Test script for the GetProcessInformation function implementation.
"""

import os
import sys

# Add the winappdbg directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from winappdbg.win32.kernel32 import (
    GetProcessInformation,
    GetCurrentProcess,
    PROCESS_INFORMATION_CLASS_KERNEL32,
    MEMORY_PRIORITY_INFORMATION,
    APP_MEMORY_INFORMATION,
    PROCESS_POWER_THROTTLING_STATE,
    PROCESS_PROTECTION_LEVEL_INFORMATION,
    PROCESS_LEAP_SECOND_INFO,
    PROCESS_MACHINE_INFORMATION,
    MEMORY_PRIORITY_NORMAL,
)

def test_get_process_information():
    """Test the GetProcessInformation function with various information classes."""

    # Get a handle to the current process
    hProcess = GetCurrentProcess()

    print("Testing GetProcessInformation function...")
    print(f"Process handle: {hProcess}")
    print()

    # Test ProcessMemoryPriority
    try:
        print("Testing ProcessMemoryPriority...")
        info = GetProcessInformation(hProcess, PROCESS_INFORMATION_CLASS_KERNEL32.ProcessMemoryPriority)
        print(f"  Memory Priority: {info.MemoryPriority}")
        print(f"  Expected range: 1-5 (MEMORY_PRIORITY_VERY_LOW to MEMORY_PRIORITY_NORMAL)")
        print(f"  Success: Memory priority is within expected range" if 1 <= info.MemoryPriority <= 5 else f"  Warning: Unexpected memory priority value")
        print()
    except Exception as e:
        print(f"  Error: {e}")
        print()

    # Test ProcessAppMemoryInfo
    try:
        print("Testing ProcessAppMemoryInfo...")
        info = GetProcessInformation(hProcess, PROCESS_INFORMATION_CLASS_KERNEL32.ProcessAppMemoryInfo)
        print(f"  Available Commit: {info.AvailableCommit:,} bytes")
        print(f"  Private Commit Usage: {info.PrivateCommitUsage:,} bytes")
        print(f"  Peak Private Commit Usage: {info.PeakPrivateCommitUsage:,} bytes")
        print(f"  Total Commit Usage: {info.TotalCommitUsage:,} bytes")
        print(f"  Success: Retrieved app memory information")
        print()
    except Exception as e:
        print(f"  Error: {e}")
        print()

    # Test ProcessPowerThrottling
    try:
        print("Testing ProcessPowerThrottling...")
        info = GetProcessInformation(hProcess, PROCESS_INFORMATION_CLASS_KERNEL32.ProcessPowerThrottling)
        print(f"  Version: {info.Version}")
        print(f"  Control Mask: 0x{info.ControlMask:08x}")
        print(f"  State Mask: 0x{info.StateMask:08x}")
        print(f"  Success: Retrieved power throttling information")
        print()
    except Exception as e:
        print(f"  Error: {e}")
        print()

    # Test ProcessProtectionLevelInfo
    try:
        print("Testing ProcessProtectionLevelInfo...")
        info = GetProcessInformation(hProcess, PROCESS_INFORMATION_CLASS_KERNEL32.ProcessProtectionLevelInfo)
        print(f"  Protection Level: 0x{info.ProtectionLevel:08x}")
        print(f"  Success: Retrieved protection level information")
        print()
    except Exception as e:
        print(f"  Error: {e}")
        print()

    # Test ProcessMachineTypeInfo
    try:
        print("Testing ProcessMachineTypeInfo...")
        info = GetProcessInformation(hProcess, PROCESS_INFORMATION_CLASS_KERNEL32.ProcessMachineTypeInfo)
        print(f"  Process Machine: 0x{info.ProcessMachine:04x}")
        print(f"  Res0: 0x{info.Res0:04x}")
        print(f"  Machine Type Attributes: 0x{info.MachineTypeAttributes:08x}")
        print(f"  Success: Retrieved machine type information")
        print()
    except Exception as e:
        print(f"  Error: {e}")
        print()

    # Test invalid information class
    try:
        print("Testing invalid ProcessInformationClass...")
        info = GetProcessInformation(hProcess, 999)  # Invalid class
        print(f"  Unexpected success with invalid class")
        print()
    except ValueError as e:
        print(f"  Expected error: {e}")
        print()
    except Exception as e:
        print(f"  Unexpected error: {e}")
        print()

if __name__ == "__main__":
    test_get_process_information()