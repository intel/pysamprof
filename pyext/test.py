#!/usr/bin/env python
import pysamprof
import threading
import os
import errno
import sys
import subprocess

def start_collection():
    counter = 0
    while True:
        target_path = '%s/results/%s' % (os.getcwd(), counter)
        if os.path.exists(target_path):
            counter += 1
        else:
            break
    pysamprof.start(target_path)

def task():
    import time
    import socket
    stop = time.time() + 1
    while time.time() <= stop:
        pass

if __name__ == '__main__':
#    proc = subprocess.Popen([sys.executable,
#                os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), 'subtest.py')])
    start_collection()
    th = threading.Thread(target=task)
    th.start()
    th.join()
#    proc.wait()

