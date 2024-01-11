# server ktery ma dva endpointy start/stop, ktery spousti a vypina funkci na pozadi

import tornado.ioloop
import tornado.web
import threading
from time import time

class MainHandler(tornado.web.RequestHandler):
    def get(self):
        self.write("Tornado server is running.")

class MiningHandler(tornado.web.RequestHandler):
    def get(self, action):
        global t
        if action == "start":
            t = threading.Thread(target=mining, args=("text",))
            t.start()
            self.write("Tornado server has started the function def mining() in the background.")
        elif action == "stop":
            t.do_run = False
            t.join()
            self.write("Tornado server has stopped the function def mining() running in the background.")


def mining(text):
    t = threading.currentThread()
    while getattr(t, "do_run", True):
        print(f"def mining() is running in the background. {text} {time()}")

def make_app():
    return tornado.web.Application([
        (r"/", MainHandler),
        (r"/(start|stop)", MiningHandler),
    ])

if __name__ == "__main__":
    app = make_app()
    app.listen(8888)
    tornado.ioloop.IOLoop.current().start()
