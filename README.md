# Sampling Profiler for Python   [![Build Status](https://travis-ci.org/intel-go/pysamprof.svg?branch=master)](https://travis-ci.org/intel-go/pysamprof)

This tool allows to gather statistical profile of CPU usage of mixed native-Python code.
Currently supported platforms are Windows and Linux, x86_64 only.

[Quick usage guide for Ubuntu 18.04](https://github.com/intel-go/pysamprof/wiki/Example-of-trace-display-on-Ubuntu-18.04).

### Required for Linux:
* `python-dev` package
* `setuptools` python package
* `autoconf` tool
* `libtool`
* `make` tool
* `unzip` tool
* `g++` compiler
* `pkg-config` tool
* `cmake` tool

### Required for Windows:
* `python` installed
* `cmake`
* Visual Studio compilers, version depends on which Python version you want to target, see [correct MSVC version](https://wiki.python.org/moin/WindowsCompilers)


### Before building do:
* On Linux:
  * `git submodule update --init --recursive`
  * `cd 3rd_party && ./prereq-build.sh && cd ..`
* On Windows:
  * Update third-party intel-xed, mbuild, protobuf, protobuf-c and safestringlib submodules (`3rd_party` folder):
      * `git submodule update --init -- .\3rd_party\intel-xed`
      * `git submodule update --init -- .\3rd_party\mbuild`
      * `git submodule update --init -- .\3rd_party\protobuf`
      * `git submodule update --init -- .\3rd_party\protobuf-c`
      * `git submodule update --init -- .\3rd_party\safestringlib`
  * Apply protobuf-c-vs2008-support.patch (step is required for Python 2 target only):
      * `cd 3rd_party\protobuf-c && git apply ..\protobuf-c-vs2008-support.patch && cd ..\..`
  * If you have installed VS2017 or VS2019, apply next command (optional step) in the same command line prompt window in which next command will be applied (please note, that path to the vcvars64.bat file may vary by version of VS installed):
      * `CALL "C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver=14.0`
  * For Python 2.x run:
    * `cd 3rd_party && prereq-build-py2.cmd && cd ..`
  * For Python 3.5 or 3.6 run:
    * `cd 3rd_party && prereq-build-py3.cmd && cd ..`
  * For other versions of 3.x (untested) try fixing the file up specifying [correct MSVC version](https://wiki.python.org/moin/WindowsCompilers)

### For building do:
* `mkdir pyext/build`
* `cd pyext/build`
* On Windows:
    * For Python 2.x:
      * `cmake -G "Visual Studio 9 2008 Win64" -DCMAKE_BUILD_TYPE=Release .. -DPYTHON_EXECUTABLE=path\to\python.exe`
    * For Python 3.5 or 3.6:
      * `cmake -G "Visual Studio 14 2015 Win64" -DCMAKE_BUILD_TYPE=Release .. -DPYTHON_EXECUTABLE=path\to\python.exe`
    * Open generated "pysamprof.sln" with VS2008 (if Python 2) or VS2015 (if Python 3), choose "Release" "x64" as solution configuration
    * Build solution
    * Copy `Release\pysamprof.pyd` and `trace_writer\Release\pysamprof-server.exe` to desired location
* On Linux:
    * `cmake -DCMAKE_BUILD_TYPE=Release .. -DPYTHON_EXECUTABLE=path/to/python`
    * `make`
    * Copy `pysamprof.so` and `trace_writer/pysamprof-server` to desired location
* **NOTE**: specifying `-DPYTHON_EXECUTABLE=path/to/python` will force which Python version to compile against; if omitted it will select highest available Python on your system.

### To use:
* Add path to location which has `pysamprof` and `pysamprof-server` inside to `PYTHONPATH`
* Do `import pysamprof` then `pysamprof.start(target_path)`, see `pyext/test.py` as a quick reference
