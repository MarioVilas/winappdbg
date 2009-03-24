# Example #7
# http://code.google.com/p/python-winappdbg/wiki/Instrumentation#Example_#7:_freeze_all_threads_in_a_process

from winappdbg import Process, System

def freeze_threads( pid ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup the threads in the process
    process.scan_threads()
    
    # For each thread in the process...
    for thread in process:
        
        # Suspend the thread execution
        thread.suspend()

def unfreeze_threads( pid ):
    
    # Request debug privileges
    System.request_debug_privileges()
    
    # Instance a Process object
    process = Process( pid )
    
    # Lookup the threads in the process
    process.scan_threads()
    
    # For each thread in the process...
    for thread in process:
        
        # Resume the thread execution
        thread.resume()

# When invoked from the command line,
# the first argument is a process ID
if __name__ == "__main__":
    import sys
    pid = int( sys.argv[1] )
    freeze_threads( pid )
##    unfreeze_threads( pid )   # to reverse the effect
