#!/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2009-2018, Mario Vilas
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

from winappdbg import System, win32

def show_services():

    # Get the list of services.
    services = System.get_services()

    # You could get only the running services instead.
    # services = System.get_active_services()

    # For each service descriptor...
    for descriptor in services:

        # Print the service information, the easy way.
        # print str(descriptor)

        # You can also do it the hard way, accessing its members.
        print "Service name: %s" % descriptor.ServiceName
        print "Display name: %s" % descriptor.DisplayName
        if   descriptor.ServiceType & win32.SERVICE_INTERACTIVE_PROCESS:
            print "Service type: Win32 GUI"
        elif descriptor.ServiceType & win32.SERVICE_WIN32:
            print "Service type: Win32"
        elif descriptor.ServiceType & win32.SERVICE_DRIVER:
            print "Service type: Driver"
        if   descriptor.CurrentState == win32.SERVICE_CONTINUE_PENDING:
            print "Current status: RESTARTING..."
        elif descriptor.CurrentState == win32.SERVICE_PAUSE_PENDING:
            print "Current status: PAUSING..."
        elif descriptor.CurrentState == win32.SERVICE_PAUSED:
            print "Current status: PAUSED"
        elif descriptor.CurrentState == win32.SERVICE_RUNNING:
            print "Current status: RUNNING"
        elif descriptor.CurrentState == win32.SERVICE_START_PENDING:
            print "Current status: STARTING..."
        elif descriptor.CurrentState == win32.SERVICE_STOP_PENDING:
            print "Current status: STOPPING..."
        elif descriptor.CurrentState == win32.SERVICE_STOPPED:
            print "Current status: STOPPED"
        print

# When invoked from the command line,
# call the show_services() function.
if __name__ == "__main__":
    show_services()
