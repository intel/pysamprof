@echo off
set ORIG_DIR=%cd%
pushd %~dp0
setlocal

pushd ..
set TARGET_DIR=%CD%\build
mkdir %TARGET_DIR%
popd

:xed
pushd .\intel-xed
python mfile.py --msvs-version=%1 --install-dir="%TARGET_DIR%\xedkit" install && echo "XED built successfully"
popd

:protobuf
pushd .\protobuf\cmake
mkdir %TARGET_DIR%\protobuf-kit-debug
mkdir build\debug
pushd build\debug
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=%TARGET_DIR%\protobuf-kit-debug -Dprotobuf_BUILD_TESTS=OFF ^
 -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_MSVC_STATIC_RUNTIME=OFF ^
 ..\..
nmake
nmake install
popd

set PROTOC=..\..\..\build\protobuf-kit-debug\bin\protoc.exe
pushd ..\python
python setup.py build
popd

rem Now build protobuf release
mkdir %TARGET_DIR%\protobuf-kit-release
mkdir build\release
pushd build\release
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=%TARGET_DIR%\protobuf-kit-release ^
 -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_MSVC_STATIC_RUNTIME=OFF ^
 ..\..
nmake
nmake install
popd

:protobuf-end
popd

:protobuf-c
pushd .\protobuf-c\build-cmake

mkdir %TARGET_DIR%\protobufc-kit-debug
mkdir build\debug
pushd build\debug
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX=%TARGET_DIR%\protobufc-kit-debug ^
 -DProtobuf_INCLUDE_DIR=%TARGET_DIR%\protobuf-kit-debug\include -DProtobuf_LIBRARIES=%TARGET_DIR%\protobuf-kit-debug\lib ^
 -DProtobuf_PROTOC_LIBRARY=%TARGET_DIR%\protobuf-kit-debug\lib\libprotocd.lib ^
 -DProtobuf_PROTOC_EXECUTABLE=%TARGET_DIR%\protobuf-kit-debug\bin\protoc.exe ^
 -DPROTOBUF_LIBRARY=%TARGET_DIR%\protobuf-kit-debug\lib\libprotobufd.lib ^
 -DENABLE_DEBUG_TESTS=OFF ^
 ..\..
nmake
nmake install
popd

mkdir %TARGET_DIR%\protobufc-kit-release
mkdir build\release
pushd build\release
cmake -G "NMake Makefiles" -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=%TARGET_DIR%\protobufc-kit-release ^
 -DProtobuf_INCLUDE_DIR=%TARGET_DIR%\protobuf-kit-release\include -DProtobuf_LIBRARIES=%TARGET_DIR%\protobuf-kit-release\lib ^
 -DProtobuf_PROTOC_LIBRARY=%TARGET_DIR%\protobuf-kit-release\lib\libprotoc.lib ^
 -DProtobuf_PROTOC_EXECUTABLE=%TARGET_DIR%\protobuf-kit-release\bin\protoc.exe ^
 -DPROTOBUF_LIBRARY=%TARGET_DIR%\protobuf-kit-release\lib\libprotobuf.lib ^
 ..\..
nmake
nmake install
popd

:protobuf-c-end
popd

popd
:finish
cd /d %ORIG_DIR%
endlocal
