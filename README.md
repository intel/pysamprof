# Sampling Profiler for Python

This tool allows to gather statistical profile of CPU usage of mixed native-Python code.
Currently supported platforms are Windows and Linux, x86_64 only.

Before building do:
* `git submodule update --init --recursive`
* `cd 3rd_party/protobuf-c && git apply ../protobuf-c-vs2008-support.patch`
* `cd 3rd_party && prereq-build.cmd` if Windows
* `cd 3rd_party && ./prereq-build.sh` if Linux
