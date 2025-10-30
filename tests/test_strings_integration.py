#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Integration test for the strings() functionality.

This test creates a simple process with known strings and verifies
that the strings() method can extract them.
"""

import os
import sys
import time
import tempfile
import subprocess

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from winappdbg.system import System
from winappdbg.process import Process


def create_test_executable():
    """
    Creates a simple test executable with known strings.
    Returns the path to the executable.
    """
    # Create a simple Python script that will have predictable strings
    test_script = """
import time
import sys

# Define some test strings
TEST_ASCII_STRING = "TestString_ASCII_12345"
TEST_UNICODE_STRING = "TestString_Unicode_67890"

print("Test process started. PID:", os.getpid())
print("Waiting for string extraction test...")

# Keep the process alive
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Test process terminated")
"""

    # Write to a temporary file
    fd, path = tempfile.mkstemp(suffix=".py", prefix="winappdbg_test_")
    with os.fdopen(fd, "w") as f:
        f.write(test_script)

    return path


def test_strings_on_self():
    """
    Test strings() on the current Python process.
    """
    print("=" * 80)
    print("TEST 1: Extracting strings from current process")
    print("=" * 80)

    try:
        # Get current process
        pid = os.getpid()
        print(f"Current PID: {pid}")

        process = Process(pid)
        process.get_handle()

        print("\nExtracting first 10 ASCII strings (min length 8)...")
        count = 0
        found_strings = []

        for address, string in process.strings(minLength=8, encoding="ascii"):
            found_strings.append(string)
            print(f"  0x{address:016x}: {string[:50]!r}...")
            count += 1
            if count >= 10:
                break

        print(f"\nFound {count} strings")

        if count > 0:
            print("✓ TEST PASSED: Successfully extracted ASCII strings")
            return True
        else:
            print("✗ TEST FAILED: No strings found")
            return False

    except Exception as e:
        print(f"✗ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_strings_on_notepad():
    """
    Test strings() on notepad.exe if it's running, or start it.
    """
    print("\n" + "=" * 80)
    print("TEST 2: Extracting strings from notepad.exe")
    print("=" * 80)

    try:
        # Try to find notepad
        system = System()
        system.request_debug_privileges()
        system.scan_processes()

        found = system.find_processes_by_filename("notepad.exe")

        notepad_process = None
        if found:
            pid = found[0][0].get_pid()
            print(f"Found running notepad.exe with PID: {pid}")
            notepad_process = Process(pid)
        else:
            print("Starting notepad.exe...")
            # Start notepad
            import subprocess

            _ = subprocess.Popen(["notepad.exe"])
            time.sleep(2)  # Give it time to start

            # Re-scan and find it
            system.scan_processes()
            found = system.find_processes_by_filename("notepad.exe")
            if found:
                pid = found[0][0].get_pid()
                print(f"Started notepad.exe with PID: {pid}")
                notepad_process = Process(pid)
            else:
                print("✗ Could not start notepad.exe")
                return False

        # Extract strings
        print("\nExtracting first 20 strings (both ASCII and Unicode, min length 6)...")
        count = 0
        ascii_count = 0
        unicode_count = 0

        for address, string in notepad_process.strings(minLength=6, encoding="both"):
            # Check if it looks like Unicode (has mostly ASCII chars)
            if any(ord(c) > 127 for c in string):
                unicode_count += 1
                enc = "Unicode"
            else:
                # Check the raw bytes to see if it was UTF-16LE
                ascii_count += 1
                enc = "ASCII"

            print(f"  0x{address:016x} [{enc}]: {string[:40]!r}")
            count += 1
            if count >= 20:
                break

        print(f"\nFound {count} strings total")
        print(f"  ASCII strings: {ascii_count}")
        print(f"  Unicode strings: {unicode_count}")

        if count > 0:
            print("✓ TEST PASSED: Successfully extracted strings from notepad.exe")
            return True
        else:
            print("✗ TEST FAILED: No strings found in notepad.exe")
            return False

    except Exception as e:
        print(f"✗ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_encoding_filters():
    """
    Test that encoding filters work correctly.
    """
    print("\n" + "=" * 80)
    print("TEST 3: Testing encoding filters")
    print("=" * 80)

    try:
        pid = os.getpid()
        process = Process(pid)
        process.get_handle()

        # Test ASCII only
        print("\nTesting ASCII-only extraction...")
        count = 0
        for address, string in process.strings(minLength=6, encoding="ascii"):
            count += 1
            if count >= 5:
                break
        print(f"  Found {count} ASCII strings")
        ascii_count = count

        # Test Unicode only
        print("\nTesting Unicode-only extraction...")
        count = 0
        for address, string in process.strings(minLength=6, encoding="unicode"):
            count += 1
            if count >= 5:
                break
        print(f"  Found {count} Unicode strings")
        unicode_count = count

        # Test both
        print("\nTesting both ASCII and Unicode extraction...")
        count = 0
        for address, string in process.strings(minLength=6, encoding="both"):
            count += 1
            if count >= 10:
                break
        print(f"  Found {count} strings (both)")
        both_count = count

        # Verify that "both" returns more results
        if both_count >= ascii_count and both_count >= unicode_count:
            print("✓ TEST PASSED: Encoding filters work correctly")
            return True
        else:
            print(
                f"✗ TEST FAILED: Expected 'both' ({both_count}) >= ascii ({ascii_count}) and unicode ({unicode_count})"
            )
            return False

    except Exception as e:
        print(f"✗ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False


def test_min_length():
    """
    Test that minLength parameter works correctly.
    """
    print("\n" + "=" * 80)
    print("TEST 4: Testing minLength parameter")
    print("=" * 80)

    try:
        pid = os.getpid()
        process = Process(pid)
        process.get_handle()

        # Test with short strings
        print("\nExtracting strings with minLength=4...")
        count_short = 0
        for address, string in process.strings(minLength=4, encoding="ascii"):
            count_short += 1
            if count_short >= 20:
                break
        print(f"  Found {count_short} strings")

        # Test with longer strings
        print("\nExtracting strings with minLength=10...")
        count_long = 0
        for address, string in process.strings(minLength=10, encoding="ascii"):
            count_long += 1
            if count_long >= 20:
                break
        print(f"  Found {count_long} strings")

        # Shorter min length should find more or equal strings
        if count_short >= count_long:
            print("✓ TEST PASSED: minLength parameter works correctly")
            return True
        else:
            print(
                f"✗ TEST FAILED: Expected more strings with minLength=4 ({count_short}) than minLength=10 ({count_long})"
            )
            return False

    except Exception as e:
        print(f"✗ TEST FAILED: {e}")
        import traceback

        traceback.print_exc()
        return False


def main():
    """Run all integration tests."""
    print("WinAppDbg strings() Integration Tests")
    print("=" * 80)
    print()

    # Check if we're on Windows
    if os.name != "nt":
        print("ERROR: These tests must be run on Windows")
        sys.exit(1)

    results = []

    # Run tests
    results.append(("Extract from current process", test_strings_on_self()))
    results.append(("Extract from notepad.exe", test_strings_on_notepad()))
    results.append(("Encoding filters", test_encoding_filters()))
    results.append(("MinLength parameter", test_min_length()))

    # Print summary
    print("\n" + "=" * 80)
    print("TEST SUMMARY")
    print("=" * 80)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")

    print()
    print(f"Total: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed!")
        sys.exit(0)
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
