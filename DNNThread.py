import threading


class DNNThread(threading.Thread):
    def __init__(self, action):
        super().__init__()
        self.action = action
        self.pause = False
        self.stop = False

    def run(self):
        while self.stop is False:
            if self.pause is False and self.action is not None:
                self.action()
