if(args.sysinfo):
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

    print table.getOutput()

    exit()