import tkinter as tk
import threading
import random
import string
import time
import os

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("generator")
        self.root.geometry("300x50")
        self.is_running = False
        self.start_stop_button = tk.Button(self.root, text="Start", command=self.toggle, bg="green")
        self.start_stop_button.pack()

    def toggle(self):
        if self.is_running:
            self.is_running = False
            self.start_stop_button.config(text="Start", bg="green")
        else:
            self.is_running = True
            self.start_stop_button.config(text="Stop", bg="red")
            self.start_writing()

    def start_writing(self):
        def run():
            while self.is_running:
                with open("buffer.txt", "a") as f:
                    f.write(" correct "+''.join(random.choices(string.ascii_uppercase + string.digits, k=10)) + "correct" + "\n")
                time.sleep(5)

        threading.Thread(target=run).start()

root = tk.Tk()
app = App(root)
root.mainloop()
