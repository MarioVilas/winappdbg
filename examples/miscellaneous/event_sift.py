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
if __name__ == "__main__":
    handler = EventSift(MyEventHandler)
    #handler = MyEventHandler()  # try uncommenting this line...
    with Debug(handler) as debug:
        debug.execl("calc.exe")
        debug.execl("notepad.exe")
        debug.execl("charmap.exe")
        debug.loop()
