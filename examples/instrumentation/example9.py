# $Id$
# Example #9
# http://apps.sourceforge.net/trac/winappdbg/wiki/wiki/Instrumentation#Example9:printathreadscontext

from winappdbg import Thread, CrashDump, System

def print_thread_context( tid ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Thread object
    thread = Thread( tid )
    
    # Suspend the thread execution
    thread.suspend()
    
    # Get the thread context
    try:
        context = thread.get_context()
    
    # Resume the thread execution
    finally:
        thread.resume()
    
    # Display the thread context
    print
    print CrashDump.dump_registers( context ),

# When invoked from the command line,
# the first argument is a thread ID
# (use example3.py to enumerate threads)
if __name__ == "__main__":
    import sys
    tid = int( sys.argv[1] )
    print_thread_context( tid )
