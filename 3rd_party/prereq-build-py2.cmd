@echo off

call "C:\Program Files (x86)\Microsoft Visual Studio 9.0\VC\vcvarsall.bat" amd64
call "%~dp0\prereq-build-novs.cmd"
