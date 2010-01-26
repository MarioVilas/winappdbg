#!/usr/bin/env python

# Copyright (c) 2009-2001, Mario Vilas
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

__revision__ = "$Id$"

from distutils.core import setup
from glob import glob
from os.path import join

# Use py2exe if installed
try:
    import py2exe
except ImportError:
    py2exe = None

# Get the list of supported database modules
import anydbm
try:
    _names = anydbm._names
except NameError:
    _names = ['dbhash', 'gdbm', 'dbm', 'dumbdbm']
dbnames = ['anydbm', 'whichdb']
for name in _names:
    try:
        __import__(name)
        dbnames.append(name)
    except ImportError:
        pass

# Text describing the module (reStructured text)
long_description = \
"""What is WinAppDbg?
==================

The WinAppDbg python module allows developers to quickly code instrumentation
scripts in Python under a Windows environment.

It uses ctypes to wrap many Win32 API calls related to debugging, and provides
an object-oriented abstraction layer to manipulate threads, libraries and
processes, attach your script as a debugger, trace execution, hook API calls,
handle events in your debugee and set breakpoints of different kinds (code,
hardware and memory). Additionally it has no native code at all, making it
easier to maintain or modify than other debuggers on Windows.

The intended audience are QA engineers and software security auditors wishing to
test / fuzz Windows applications with quickly coded Python scripts. Several
ready to use utilities are shipped and can be used for this purposes.

Current features also include disassembling x86 native code (using the open
source diStorm project, see http://ragestorm.net/distorm/), debugging multiple
processes simultaneously and produce a detailed log of application crashes,
useful for fuzzing and automated testing.

Where can I find WinAppDbg?
===========================

Project homepage:
-----------------

http://tinyurl.com/winappdbg

Download links:
---------------

Windows installer (32 bits)

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win32.exe/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win32-py2.4.msi/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win32-py2.5.msi/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win32-py2.6.msi/download

Windows installer (64 bits)

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win-amd64.exe/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win-amd64-py2.4.msi/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win-amd64-py2.5.msi/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.win-amd64-py2.6.msi/download

Source code

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.zip/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.tar.bz2/download

Documentation:
--------------

Online

http://winappdbg.sourceforge.net/doc/v1.4/

http://sourceforge.net/apps/trac/winappdbg/wiki/ProgrammingGuide

For download:

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.chm/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.pdf/download

http://sourceforge.net/projects/winappdbg/files/WinAppDbg/1.4/winappdbg-1.4.ps/download
"""

# Get the list of scripts in the "tools" folder
scripts = glob(join('tools', '*.py'))

# Set the options for py2exe
if py2exe is None:
    options = {}
else:
    options = {
        'py2exe': {
            'dist_dir'      :   'dist/py2exe',
            'optimize'      :   2,
            'compressed'    :   1,
            'packages'      :   ['encodings'] + dbnames,
            'excludes'      :   [
                                'doctest', 'pdb', 'unittest', 'difflib', 'inspect',
                                'calendar', 'socket', 'pyreadline'
                                ],
        }
    }

# Set the parameters for the setup script
params = {

    # Setup instructions
    'requires'          : ['ctypes'],
    'provides'          : ['winappdbg'],
    'packages'          : ['winappdbg', 'winappdbg.win32'],
    'scripts'           : scripts,
    'options'           : options,

    # Metadata
    'name'              : 'winappdbg',
    'version'           : '1.4',
    'description'       : 'Windows application debugging engine',
    'long_description'  : long_description,
    'author'            : 'Mario Vilas',
    'author_email'      : 'mvilas'+chr(64)+'gmail'+chr(0x2e)+'com',
    'url'               : 'http://winappdbg.sourceforge.net/',
    'download_url'      : 'http://sourceforge.net/projects/winappdbg/',
    'platforms'         : ['win32', 'cygwin'],
    'classifiers'       : [
                        'License :: OSI Approved :: BSD License',
                        'Development Status :: 5 - Production/Stable',
                        'Environment :: Console',
                        'Intended Audience :: Developers',
                        'Natural Language :: English',
                        'Operating System :: Microsoft :: Windows',
                        'Programming Language :: Python :: 2.4',
                        'Programming Language :: Python :: 2.5',
                        'Programming Language :: Python :: 2.6',
                        'Topic :: Software Development :: Debuggers',
                        'Topic :: Software Development :: Libraries :: Python Modules',
                        ],
    }
if py2exe is not None:
    params['console'] = scripts

# Execute the setup script
setup(**params)
