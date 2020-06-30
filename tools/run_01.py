import winappdbg
import argparse
from winappdbg import win32

import sys

def main():
    parser = argparse.ArgumentParser(description="WinAppDbg stuff.")
    parser.add_argument("-r", "--run", help="path to application")
    parser.add_argument("-s", "--sysinfo",action='store_true', help="get System module 's information")
    parser.add_argument("-p","--process",action='store_true', help="get all running processes")
    parser.add_argument("-pname","--attach-pname",type=str,dest="pname", help="attach to th pname process")


    args = parser.parse_args()

    # Use Win32 API functions provided by WinAppDbg
    if win32.PathFileExists(args.run) is True:
        # File exists

        # Create a Debug object
        debug = winappdbg.Debug()

        try:
            # Debug the app
            # First item is program and the rest are arguments
            # execv: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/debug.py#L274
            my_process = debug.execv([args.run])

            print("Attached to %d - %s" % (my_process.get_pid(),
                                           my_process.get_filename()))

            # Keep debugging until the debugger stops
            debug.loop()

        finally:
            # Stop the debugger
            debug.stop()
            print("Debugger stopped.")
    
    elif args.sysinfo:
        # Create a System object
        # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/system.py#L66
        system = winappdbg.System()

        # Use the built-in WinAppDbg table
        # https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/textio.py#L1094
        table = winappdbg.Table("\t")

        # New line
        table.addRow("", "")

        # Header
        title = ("System Information", "")
        table.addRow(*title)

        # Add system information
        table.addRow("------------------")
        table.addRow("Bits", system.bits)
        table.addRow("OS", system.os)
        table.addRow("Architecture", system.arch)
        table.addRow("32-bit Emulation", system.wow64)
        table.addRow("Admin", system.is_admin())
        table.addRow("WinAppDbg", winappdbg.version)
        table.addRow("Process Count", system.get_process_count())

        print(table.getOutput())

        table1 = winappdbg.Table("\t")

        table1.addRow( "Right justified column text", "Left justified column text" )
        table1.addRow( "---------------------------", "--------------------------" )
        table1.addRow( "example", "text" )
        table1.addRow( "jabberwocky", "snark" )
        table1.addRow( "Trillian", "Zaphod", "Arthur Dent" )     # one extra!
        table1.addRow( "Dalek", "Cyberman" )

        # By default all columns are left justified. Let's change that.
        table1.justify( 0, 1 )  # column 0 is now right justified

        # Let's find out how wide the table is.
        print("Table width: %d" % table1.getWidth())

        # Let's find out how many bytes would it be if written to a file.
        print("Text size in characters: %d" % len( table1.getOutput() ))

        print(table1.getOutput())

    elif args.process:
        system = winappdbg.System()

        # We can reuse example 02 from the docs
        # https://winappdbg.readthedocs.io/en/latest/Instrumentation.html#example-2-enumerating-running-processes
        table = winappdbg.Table("\t")
        table.addRow("", "")

        header = ("pid", "process")
        table.addRow(*header)

        table.addRow("----", "----------")

        processes = {}

        # Add all processes to a dictionary then sort them by pid
        for process in system:
            processes[process.get_pid()] = process.get_filename()

        # Iterate through processes sorted by pid
        for key in sorted(processes.keys()):
            table.addRow(key, processes[key])

        print(table.getOutput())

    elif args.pname:
        debug = winappdbg.Debug()

        # example 3:
        # https://winappdbg.readthedocs.io/en/latest/_downloads/03_find_and_attach.py

        try:
            debug.system.scan()
            for (process, name) in debug.system.find_processes_by_filename(args.pname):
                print("Found %d, %s" % (process.get_pid(),
                                        process.get_filename()))

                debug.attach(process.get_pid())

                print("Attached to %d-%s" % (process.get_pid(),
                                            process.get_filename()))

            debug.loop()

        finally:
            debug.stop()

    else:
        print("%s not found." % (args.run))

def main1():
    parser = argparse.ArgumentParser(description="WinAppDbg stuff.")
    parser.add_argument("-r", "--run", nargs="+",
                        help="path to application followed by parameters")

    args = parser.parse_args()

    if (args.run):
        # Concat all arguments into a string
        myargs = " ".join(args.run)

        # Use Win32 API functions provided by WinAppDbg
        if win32.PathFileExists(args.run[0]) is True:
            # File exists

            # Create a Debug object
            debug = winappdbg.Debug()

            try:
                # Debug the app
                # Debug.execv([args.app])
                # execl: https://github.com/MarioVilas/winappdbg/blob/master/winappdbg/debug.py#L358
                my_process = debug.execl(myargs)

                print("Started %d - %s" % (my_process.get_pid(),
                                           my_process.get_filename()))

                # Keep debugging until the debugger stops
                debug.loop()

            finally:
                # Stop the debugger
                debug.stop()
                print("Debugger stopped.")

        else:
            print("%s not found." % (args.run[0]))

if __name__ == "__main__":
    #main(['-r', 'c:\\windows\\system32\\notepad.exe'])
    main()