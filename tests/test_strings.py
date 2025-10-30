#!/usr/bin/python3
# -*- coding: utf-8 -*-

"""
Unit tests for the strings() functionality.
"""

import unittest
from winappdbg.search import AsciiStringsPattern, UnicodeStringsPattern


class TestAsciiStringsPattern(unittest.TestCase):
    """Test the AsciiStringsPattern class."""

    def test_basic_extraction(self):
        """Test basic ASCII string extraction."""
        pattern = AsciiStringsPattern(minLength=4)
        data = b"Hello World! This is a test."

        # Initialize the pattern with data
        pattern.data = data
        pattern.pos = 0

        # Find first match
        pos = pattern.next_match()
        self.assertGreaterEqual(pos, 0)
        self.assertEqual(
            data[pos : pos + len(pattern)], b"Hello World! This is a test."
        )

    def test_minimum_length(self):
        """Test minimum length filtering."""
        pattern = AsciiStringsPattern(minLength=10)
        data = b"Hi\x00\x00Long enough string here\x00Short"

        pattern.data = data
        pattern.pos = 0

        # Should find the long string
        pos = pattern.next_match()
        self.assertGreaterEqual(pos, 0)
        match = data[pos : pos + len(pattern)]
        self.assertGreaterEqual(len(match), 10)

    def test_binary_data_filtering(self):
        """Test that binary data is filtered out."""
        pattern = AsciiStringsPattern(minLength=4)
        data = b"\x00\x01\x02\x03Hello\x00\x01\x02World"

        pattern.data = data
        pattern.pos = 0

        # Find first string
        pos = pattern.next_match()
        self.assertGreaterEqual(pos, 0)
        match = data[pos : pos + len(pattern)]
        self.assertEqual(match, b"Hello")

        # Find next string
        pattern.pos = pos + len(pattern)
        pos = pattern.next_match()
        self.assertGreaterEqual(pos, 0)
        match = data[pos : pos + len(pattern)]
        self.assertEqual(match, b"World")

    def test_no_match(self):
        """Test when no strings are found."""
        pattern = AsciiStringsPattern(minLength=4)
        data = b"\x00\x01\x02\x03\x04\x05"

        pattern.data = data
        pattern.pos = 0

        # Should not find any strings
        pos = pattern.next_match()
        self.assertEqual(pos, -1)

    def test_multiple_strings(self):
        """Test extracting multiple strings from data."""
        pattern = AsciiStringsPattern(minLength=4)
        data = b"First\x00\x00Second\x00Third"

        pattern.data = data
        pattern.pos = 0

        strings = []
        while True:
            pos = pattern.next_match()
            if pos < 0:
                break
            match = data[pos : pos + len(pattern)]
            strings.append(match)
            pattern.pos = pos + len(pattern)

        self.assertEqual(len(strings), 3)
        self.assertEqual(strings[0], b"First")
        self.assertEqual(strings[1], b"Second")
        self.assertEqual(strings[2], b"Third")


class TestUnicodeStringsPattern(unittest.TestCase):
    """Test the UnicodeStringsPattern class."""

    def test_basic_extraction(self):
        """Test basic Unicode string extraction."""
        pattern = UnicodeStringsPattern(minLength=4)
        # "Hello" in UTF-16LE
        data = b"H\x00e\x00l\x00l\x00o\x00"

        pattern.data = data
        pattern.pos = 0

        # Find match
        pos = pattern.next_match()
        self.assertGreaterEqual(pos, 0)
        match = data[pos : pos + len(pattern)]
        self.assertEqual(match, b"H\x00e\x00l\x00l\x00o\x00")

    def test_minimum_length(self):
        """Test minimum length filtering."""
        pattern = UnicodeStringsPattern(minLength=10)
        # "Hello" is too short (5 chars), "Long enough" is 11 chars
        data = (
            b"H\x00i\x00\x00\x00L\x00o\x00n\x00g\x00 \x00e\x00n\x00o\x00u\x00g\x00h\x00"
        )

        pattern.data = data
        pattern.pos = 0

        # Should skip "Hi" and find "Long enough"
        pos = pattern.next_match()
        self.assertGreaterEqual(pos, 0)
        match = data[pos : pos + len(pattern)]
        # Match should be at least 20 bytes (10 chars * 2 bytes)
        self.assertGreaterEqual(len(match), 20)

    def test_mixed_data(self):
        """Test Unicode extraction from mixed binary data."""
        pattern = UnicodeStringsPattern(minLength=4)
        # Binary data followed by "Test" in UTF-16LE
        data = b"\x00\x01\x02\x03T\x00e\x00s\x00t\x00\x00\x01\x02"

        pattern.data = data
        pattern.pos = 0

        # Find the Unicode string
        pos = pattern.next_match()
        self.assertGreaterEqual(pos, 0)
        match = data[pos : pos + len(pattern)]
        self.assertEqual(match, b"T\x00e\x00s\x00t\x00")

    def test_no_match(self):
        """Test when no Unicode strings are found."""
        pattern = UnicodeStringsPattern(minLength=4)
        # ASCII data without proper UTF-16LE encoding
        data = b"Hello World"

        pattern.data = data
        pattern.pos = 0

        # Should not find Unicode strings in ASCII data
        pos = pattern.next_match()
        self.assertEqual(pos, -1)

    def test_multiple_unicode_strings(self):
        """Test extracting multiple Unicode strings."""
        pattern = UnicodeStringsPattern(minLength=4)
        # "First" and "Second" in UTF-16LE with binary data between
        data = (
            b"F\x00i\x00r\x00s\x00t\x00\x00\x00\x01\x02S\x00e\x00c\x00o\x00n\x00d\x00"
        )

        pattern.data = data
        pattern.pos = 0

        strings = []
        while True:
            pos = pattern.next_match()
            if pos < 0:
                break
            match = data[pos : pos + len(pattern)]
            strings.append(match)
            pattern.pos = pos + len(pattern)

        self.assertEqual(len(strings), 2)
        self.assertEqual(strings[0], b"F\x00i\x00r\x00s\x00t\x00")
        self.assertEqual(strings[1], b"S\x00e\x00c\x00o\x00n\x00d\x00")


class TestPatternIntegration(unittest.TestCase):
    """Test integration of pattern classes."""

    def test_both_patterns_on_mixed_data(self):
        """Test using both ASCII and Unicode patterns on mixed data."""
        # Mix of ASCII and UTF-16LE strings
        data = (
            b"ASCII text here"
            b"\x00\x00\x01\x02"
            b"U\x00n\x00i\x00c\x00o\x00d\x00e\x00"
            b"\x00\x01\x02\x03"
            b"More ASCII"
        )

        # Test ASCII pattern
        ascii_pattern = AsciiStringsPattern(minLength=4)
        ascii_pattern.data = data
        ascii_pattern.pos = 0

        ascii_strings = []
        while True:
            pos = ascii_pattern.next_match()
            if pos < 0:
                break
            match = data[pos : pos + len(ascii_pattern)]
            ascii_strings.append(match)
            ascii_pattern.pos = pos + len(ascii_pattern)

        self.assertGreater(len(ascii_strings), 0)
        self.assertIn(b"ASCII text here", ascii_strings)
        self.assertIn(b"More ASCII", ascii_strings)

        # Test Unicode pattern
        unicode_pattern = UnicodeStringsPattern(minLength=4)
        unicode_pattern.data = data
        unicode_pattern.pos = 0

        unicode_strings = []
        while True:
            pos = unicode_pattern.next_match()
            if pos < 0:
                break
            match = data[pos : pos + len(unicode_pattern)]
            unicode_strings.append(match)
            unicode_pattern.pos = pos + len(unicode_pattern)

        self.assertGreater(len(unicode_strings), 0)
        self.assertIn(b"U\x00n\x00i\x00c\x00o\x00d\x00e\x00", unicode_strings)


if __name__ == "__main__":
    unittest.main()
