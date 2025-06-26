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

__all__ = ['metadata', 'setup']

try:
    from setuptools import setup, version
except ImportError:
    from distutils.core import setup
    from distutils import version
from warnings import warn

import re
import os
import glob

# Get the base directory
here = os.path.dirname(__file__)
if not here:
    here = os.path.curdir
here = os.path.abspath(here)

# Text describing the module (Markdown)
try:
    readme = os.path.join(here, 'README.md')
    with open(readme, 'r', encoding='utf-8') as f:
        long_description = f.read()
except Exception:
    warn("README file not found or unreadable!")
    long_description = """The WinAppDbg python module
allows developers to quickly code instrumentation scripts
in Python under a Windows environment."""

# Get the list of scripts in the "tools" folder
scripts = glob.glob(os.path.join(here, 'tools', '*.py'))

# Set the parameters for the setup script
metadata = {

    # Setup instructions
    'packages'          : ['winappdbg', 'winappdbg.win32', 'winappdbg.plugins'],
    'scripts'           : scripts,

    # Metadata
    'name'              : 'winappdbg',
    'version'           : '1.6',
    'description'       : 'Windows application debugging engine',
    'long_description'  : long_description,
    'author'            : 'Mario Vilas',
    'author_email'      : 'mvilas@gmail.com',
    'url'               : 'http://winappdbg.readthedocs.io/en/latest/',
    'download_url'      : 'https://github.com/MarioVilas/winappdbg/archive/winappdbg_v1.6.tar.gz',
    'platforms'         : ['win32', 'win64'],
    'classifiers'       : [
                        'License :: OSI Approved :: BSD License',
                        'Development Status :: 5 - Production/Stable',
                        'Environment :: Console',
                        'Intended Audience :: Developers',
                        'Natural Language :: English',
                        'Operating System :: Microsoft :: Windows',
                        'Programming Language :: Python :: 3',
                        'Topic :: Security',
                        'Topic :: Software Development :: Debuggers',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        'Topic :: Software Development :: Quality Assurance',
                        ],
    }

# Execute the setup script
if __name__ == '__main__':
    cwd = os.getcwd()
    os.chdir(here)
    try:
        setup(**metadata)
    finally:
        os.chdir(cwd)
