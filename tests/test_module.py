#!/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2020, Mario Vilas
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

import mock
import unittest
import winappdbg

class ModuleTests(unittest.TestCase):

    def assertSymbolAtAddressEqual(self, address, symbol):
        self.assertEqual(winappdbg.Module(0).get_symbol_at_address(address),
                        symbol)

    @mock.patch('winappdbg.Module.iter_symbols')
    def test_get_symbol_at_address(self, mock_iter_symbols):
        mock_iter_symbols.return_value = [("matchPattern", 0x002A, 0x10),
                                        ("isMatched", 0xFF42, 0x0090),
                                        ("__ii_95", 0x0102, 0),
                                        ("groupSize", 0x000A, 0),
                                        ("__ref_thesaurus", 0x1000, 0x07F0),
                                        ("iter_int32", 0x009E, 0x00A4),
                                        ("__jj_49", 0x0140, 0),
                                        ("numGroups", 0x001F, 0),
                                        ("__comp_state", 0x003C, 0x0004)]

        self.assertSymbolAtAddressEqual(0x000A, ("groupSize", 0x000A, 0))
        self.assertSymbolAtAddressEqual(0x0029, ("numGroups", 0x001F, 0))
        self.assertSymbolAtAddressEqual(0x0141, ("iter_int32", 0x009E, 0x00A4))
        self.assertSymbolAtAddressEqual(0x0142, ("__jj_49", 0x0140, 0))
        self.assertSymbolAtAddressEqual(0x493F, ("__ref_thesaurus", 0x1000, 0))
        self.assertSymbolAtAddressEqual(0xFF7A, ("isMatched", 0xFF42, 0x0090))
