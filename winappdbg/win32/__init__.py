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

"""
Debugging API wrappers in ctypes.
"""

# Import all submodules into this namespace.
from . import (
    advapi32,
    dbghelp,
    defines,
    kernel32,
    ntdll,
    psapi,
    shell32,
    shlwapi,
    user32,
    wtsapi32,
)
from .advapi32 import *  # NOQA
from .dbghelp import *  # NOQA

# Import all symbols from submodules into this namespace.
from .defines import *  # NOQA
from .kernel32 import *  # NOQA
from .ntdll import *  # NOQA
from .psapi import *  # NOQA
from .shell32 import *  # NOQA
from .shlwapi import *  # NOQA
from .user32 import *  # NOQA
from .wtsapi32 import *  # NOQA
from .version import *  # NOQA

# This calculates the list of exported symbols.
_all = set()
_all.update(defines._all)
_all.update(kernel32._all)
_all.update(user32._all)
_all.update(advapi32._all)
_all.update(wtsapi32._all)
_all.update(shell32._all)
_all.update(shlwapi._all)
_all.update(psapi._all)
_all.update(dbghelp._all)
_all.update(ntdll._all)
__all__ = [_x for _x in _all if not _x.startswith("_")]
__all__.sort()
