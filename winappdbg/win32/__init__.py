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

# ruff: noqa

"""
Debugging API wrappers in ctypes.
"""

# Import all submodules into this namespace.
from . import (
    advapi32,
    dbghelp,
    defines,
    gdi32,
    kernel32,
    ntdll,
    peb_teb,
    psapi,
    shell32,
    shlwapi,
    user32,
    version,
    wtsapi32,
)

# Import all symbols from submodules into this namespace.
from .advapi32 import *
from .dbghelp import *
from .defines import *
from .gdi32 import *
from .kernel32 import *
from .ntdll import *
from .peb_teb import *
from .psapi import *
from .shell32 import *
from .shlwapi import *
from .user32 import *
from .version import *
from .wtsapi32 import *

# Import the appropriate context module based on detected architecture.
if arch == ARCH_I386:
    from .context_i386 import *
    from . import context_i386 as _context_module
elif arch == ARCH_AMD64:
    from .context_amd64 import *
    from . import context_amd64 as _context_module
elif arch == ARCH_ARM64:
    from .context_arm64 import *
    from . import context_arm64 as _context_module

# This calculates the list of exported symbols.
_all = set()
_all.update(advapi32._all)
_all.update(dbghelp._all)
_all.update(defines._all)
_all.update(gdi32._all)
_all.update(kernel32._all)
_all.update(ntdll._all)
_all.update(peb_teb._all)
_all.update(psapi._all)
_all.update(shell32._all)
_all.update(shlwapi._all)
_all.update(user32._all)
_all.update(version._all)
_all.update(wtsapi32._all)
_all.update(_context_module._all)
__all__ = sorted([_x for _x in _all if not _x.startswith("_")])
