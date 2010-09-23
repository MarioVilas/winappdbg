# Copyright (c) 2009-2010, Mario Vilas
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
Python 2.x/3.x compatibility hacks.
"""

__revision__ = "$Id: defines.py 753 2010-07-14 20:19:29Z qvasimodo $"

import sys

###############################################################################
##                         Python 2.x compatibility                          ##
###############################################################################

if sys.version_info[0] == 2:

    range = xrange

    def isnumtype(x):
        return isinstance(x, int) or isinstance(x, long)

    def keys(x):
        return x.iterkeys()

    def values(x):
        return x.itervalues()

    def items(x):
        return x.iteritems()

###############################################################################
##                         Python 3.x compatibility                          ##
###############################################################################

else:
    import collections

    xrange = range
    long = int
    raw_input = input

    def next(e):
        return e.next()

    def callable(obj):
        return isinstance(obj, collections.Callable)

    def isnumtype(x):
        return isinstance(x, int)

    def keys(x):
        return x.keys()

    def values(x):
        return x.values()

    def items(x):
        return x.items()
