#!/usr/bin/env python3

"""
Test script to verify MiasmEngine integration with WinAppDbg.
"""

import sys


def test_miasm_engine_integration():
    """Test that MiasmEngine integrates properly with WinAppDbg"""

    print("=== Testing MiasmEngine Integration with WinAppDbg ===\n")

    try:
        from winappdbg.disasm import MiasmEngine, Disassembler
        import winappdbg.win32 as win32

        print("Successfully imported MiasmEngine from winappdbg.disasm")

        # Test 1: Direct MiasmEngine creation
        print("\nTest 1: Direct MiasmEngine creation")

        # Test ARM64 support
        try:
            engine = MiasmEngine(win32.ARCH_ARM64)
            print("MiasmEngine created successfully for ARM64")

            # Test ARM64 disassembly
            # mov x0, #42; ret
            arm64_code = b"\x40\x05\x80\xd2\xc0\x03\x5f\xd6"
            results = engine.decode(0x1000, arm64_code)

            print("ARM64 disassembly results:")
            for addr, size, disasm, hexdump in results:
                print(f"  {addr:08x}: {hexdump.ljust(8)} {disasm}")

        except Exception as e:
            print(f"ARM64 test failed: {e}")
            return False

        # Test x86_64 support
        try:
            engine = MiasmEngine(win32.ARCH_AMD64)
            print("MiasmEngine created successfully for x86_64")

            # Test x86_64 disassembly
            # mov rax, 42; ret
            x64_code = b"\x48\xc7\xc0\x2a\x00\x00\x00\xc3"
            results = engine.decode(0x1000, x64_code)

            print("x86_64 disassembly results:")
            for addr, size, disasm, hexdump in results:
                print(f"  {addr:08x}: {hexdump.ljust(8)} {disasm}")

        except Exception as e:
            print(f"x86_64 test failed: {e}")
            return False

        # Test 2: Generic Disassembler usage
        print("\nTest 2: Generic Disassembler usage")

        try:
            # Test that MiasmEngine is available via Disassembler
            disasm = Disassembler(engine="Miasm", arch=win32.ARCH_ARM64)
            print("MiasmEngine accessible via Disassembler")

            # Test disassembly via generic interface
            results = disasm.decode(0x2000, arm64_code)

            print("Generic disassembler results:")
            for addr, size, disasm_str, hexdump in results:
                print(f"  {addr:08x}: {hexdump.ljust(8)} {disasm_str}")

        except Exception as e:
            print(f"Generic disassembler test failed: {e}")
            return False

        # Test 3: Auto-selection (should pick MiasmEngine first)
        print("\nTest 3: Auto-selection test")

        try:
            # Test auto-selection for ARM64 (should pick MiasmEngine)
            auto_disasm = Disassembler(arch=win32.ARCH_ARM64)
            print(f"Auto-selected engine: {auto_disasm.name}")

            # Should be MiasmEngine since it's first in the list
            if auto_disasm.name == "Miasm":
                print("MiasmEngine correctly selected as first choice")
            else:
                print(f"⚠ Expected MiasmEngine, got {auto_disasm.name}")

        except Exception as e:
            print(f"Auto-selection test failed: {e}")
            return False

        # Test 4: Supported architectures
        print("\nTest 4: Supported architectures")

        expected_archs = {
            win32.ARCH_I386,
            win32.ARCH_AMD64,
            win32.ARCH_ARM,
            win32.ARCH_ARM64,
            win32.ARCH_THUMB,
        }

        if MiasmEngine.supported == expected_archs:
            print("MiasmEngine supports all expected architectures")
            print(f"  Supported: {sorted(MiasmEngine.supported)}")
        else:
            print(f"Unexpected supported architectures: {MiasmEngine.supported}")
            return False

        # Test 5: Engine metadata
        print("\nTest 5: Engine metadata")

        print(f"  Name: {MiasmEngine.name}")
        print(f"  Description: {MiasmEngine.desc}")
        print(f"  URL: {MiasmEngine.url}")

        expected_name = "Miasm"
        if MiasmEngine.name == expected_name:
            print("Engine name is correct")
        else:
            print(f"Expected name '{expected_name}', got '{MiasmEngine.name}'")
            return False

        print("\nAll tests passed! MiasmEngine integration is working correctly.")
        return True

    except ImportError as e:
        print(f"Import error: {e}")
        print("Make sure Miasm is installed:")
        print("  git clone https://github.com/cea-sec/miasm.git")
        print("  cd miasm && python setup.py install")
        return False
    except Exception as e:
        print(f"Unexpected error: {e}")
        import traceback

        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_miasm_engine_integration()
    sys.exit(0 if success else 1)
