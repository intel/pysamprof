#!/usr/bin/env python
import pysamprof
import threading
import os
import errno
import sys
import subprocess
import time

def start_collection():
    counter = 0
    while True:
        target_path = '%s/results/%s' % (os.getcwd(), counter)
        if os.path.exists(target_path):
            counter += 1
        else:
            break
    pysamprof.start(target_path, 10, 39 if sys.platform != 'win32' else 0)
    print(pysamprof.request_server_pid(10))
    my_server = pysamprof.request_server_pid(os.getpid())
    print(my_server)
    print(pysamprof.request_server_pid(my_server))

def busy_wait(timeout):
    stop = time.time() + timeout
    while time.time() <= stop:
        pass
    
def task():
    import socket
    busy_wait(1)
    pysamprof.pause_current()
    time.sleep(1.5)
    pysamprof.resume_current()
    busy_wait(1)

if __name__ == '__main__':
    start_collection()
    proc = subprocess.Popen([sys.executable,
                os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])), 'subtest.py')])
    th = threading.Thread(target=task)
    th.start()
    th.join()
#    proc.wait()

