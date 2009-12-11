from winappdbg import *
from time import time

dbg = Debug(bKillOnExit = True)
try:
    dbg.execl('calc.exe')
    maxTime = time() + 5    # 5 seconds timeout
    while dbg.get_debugee_count() > 0 and time() < maxTime:
        try:
            print time()
            event = dbg.wait(1000)
        except WindowsError, e:
            if win32.winerror(e) in (win32.ERROR_SEM_TIMEOUT, win32.WAIT_TIMEOUT):
                continue
            raise
        try:
            dbg.dispatch(event)
        finally:
            dbg.cont(event)
finally:
    dbg.stop()
