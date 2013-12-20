#!~/.wine/drive_c/Python25/python.exe
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2014, Mario Vilas
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

# $Id$

from winappdbg import Debug, EventHandler, EventSift


# This class was written assuming only one process is attached.
# If you used it directly it would break when attaching to another
# process, or when a child process is spawned.
class MyEventHandler (EventHandler):

    def create_process(self, event):
        self.first = True
        self.name = event.get_process().get_filename()
        print "Attached to %s" % self.name

    def breakpoint(self, event):
        if self.first:
            self.first = False
            print "First breakpoint reached at %s" % self.name

    def exit_process(self, event):
        print "Detached from %s" % self.name


# Now when debugging we use the EventForwarder to be able to work with
# multiple processes while keeping our code simple. :)
def simple_debugger():

    handler = EventSift(MyEventHandler)
    #handler = MyEventHandler()  # try uncommenting this line...
    with Debug(handler) as debug:
        debug.execl("calc.exe")
        debug.execl("notepad.exe")
        debug.execl("charmap.exe")
        debug.loop()


# When invoked from the command line,
# it will launch several Windows utilities and debug them.
if __name__ == "__main__":
    simple_debugger()
