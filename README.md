# Sampling Profiler for Python

This tool allows to gather statistical profile of CPU usage of mixed native-Python code.
Currently supported platforms are Windows and Linux, x86_64 only.

### Required for Linux:
* `python-dev` package
* `autoconf` tool
* `libtool`
* `make` tool
* `unzip` tool
* `g++` compiler
* `pkg-config` tool
* `cmake` tool

### Before building do:
* On Linux:
  * `git submodule update --init --recursive`
  * `cd 3rd_party && ./prereq-build.sh && cd ..`
* On Windows:
  * `git submodule update --init --recursive`
  * `cd 3rd_party/protobuf-c && git apply ../protobuf-c-vs2008-support.patch && cd ../..`
  * `cd 3rd_party && prereq-build.cmd && cd ..`

### For building do:
* `mkdir pyext/build`
* `cd pyext/build`
* On Windows:
    * `cmake -G "Visual Studio 9 2008 Win64" -DCMAKE_BUILD_TYPE=Release ..`
    * Open generated "pysamprof.sln" with VS2008, choose "Release" "x64" as solution configuration
    * Build solution
    * Copy `Release\pysamprof.pyd` and `trace_writer\Release\pysamprof-server.exe` to desired location
* On Linux:
    * `cmake -DCMAKE_BUILD_TYPE=Release ..`
    * `make`
    * Copy `pysamprof.so` and `trace_writer/pysamprof-server` to desired location

### To use:
* Add path to location which has `pysamprof` and `pysamprof-server` inside to `PYTHONPATH`
* Do `import pysamprof` then `pysamprof.start(target_path)`, see `pyext/test.py` as a quick reference
