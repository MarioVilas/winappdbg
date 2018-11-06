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

from time import sleep

from winappdbg import System, win32


# Function that restarts a service.
# Requires UAC elevation in Windows Vista and above.
def restart_service( service ):
    try:

        # Get the display name.
        try:
            display_name = System.get_service_display_name( service )
        except WindowsError:
            display_name = service

        # Get the service descriptor.
        descriptor = System.get_service( service )

        # Is the service running?
        if descriptor.CurrentState != win32.SERVICE_STOPPED:

            # Tell the service to stop.
            print "Stopping service \"%s\"..." % display_name
            System.stop_service( service )

            # Wait for the service to stop.
            wait_for_service( service, win32.SERVICE_STOP_PENDING )
            print "Service stopped successfully."

        # Tell the service to start.
        print "Starting service \"%s\"..." % display_name
        System.start_service( service )

        # Wait for the service to start.
        wait_for_service( service, win32.SERVICE_START_PENDING )
        print "Service started successfully."

        # Show the new process ID.
        # This feature requires Windows XP and above.
        descriptor = System.get_service( service )
        try:
            print "New process ID is: %d" % descriptor.ProcessId
        except AttributeError:
            pass

    # On error, show an error message.
    except WindowsError, e:
        if e.winerror == win32.ERROR_ACCESS_DENIED:
            print "Access denied! Is this an UAC elevated prompt?"
        else:
            print str(e)


# Helper function to wait for the service to change its state.
def wait_for_service( service, wait_state, timeout = 20 ):
    descriptor = System.get_service( service )
    while descriptor.CurrentState == wait_state:
        timeout -= 1
        if timeout <= 0:
            raise RuntimeError( "Error: timed out." )
        sleep( 0.5 )
        descriptor = System.get_service( service )


# When invoked from the command line,
# the first argument is a service name.
if __name__ == "__main__":
    import sys
    service = sys.argv[1]
    restart_service( service )
