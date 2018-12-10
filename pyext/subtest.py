import pysamprof
import time
import os

def main():
    print('subtest, pid: %s' % os.getpid())
    stop = time.time() + 2
    while time.time() <= stop:
        pass

if __name__ == '__main__':
    main()

