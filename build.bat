@echo off
setlocal

set LIBNAMES=DXP DXP_AES DXP_CRC DXP_SHA256 DXP_crypto DXP_keys DXP_packet DXP_process DXP_receive DXP_transmit DXP_stream DXP_link
set LIBSRC=DXP.cpp DXP_AES.cpp DXP_CRC.cpp DXP_SHA256.cpp DXP_crypto.cpp DXP_keys.cpp DXP_packet.cpp DXP_process.cpp DXP_receive.cpp DXP_transmit.cpp DXP_stream.cpp DXP_link.cpp
set LIBOBJMSVC=build\DXP.obj build\DXP_AES.obj build\DXP_CRC.obj build\DXP_SHA256.obj build\DXP_crypto.obj build\DXP_keys.obj build\DXP_packet.obj build\DXP_process.obj build\DXP_receive.obj build\DXP_transmit.obj build\DXP_stream.obj build\DXP_link.obj
set LIBOBJGNU=build/DXP.o build/DXP_AES.o build/DXP_CRC.o build/DXP_SHA256.o build/DXP_crypto.o build/DXP_keys.o build/DXP_packet.o build/DXP_process.o build/DXP_receive.o build/DXP_transmit.o build/DXP_stream.o build/DXP_link.o
set HEADERS=DXP.h DXP_packet.h DXP_process.h DXP_link.h DXP_transport.h DXP_stream.h DXP_transmit.h DXP_receive.h DXP_keys.h

set MSVCFLAGS=/nologo /c /O2 /W4 /std:c++17 /EHsc
set MSVCLINK=/nologo /O2 /W4 /std:c++17 /EHsc
set GNUTOOLS=-std=c++17 -O2 -Wall -Wextra
set GNULINK=

if /i "%~1"=="asan" set MSVCFLAGS=/nologo /c /O2 /W4 /std:c++17 /EHsc /fsanitize:address
if /i "%~1"=="asan" set MSVCLINK=/nologo /O2 /W4 /std:c++17 /EHsc /fsanitize:address
if /i "%~1"=="asan" set GNUTOOLS=-std=c++17 -O1 -g -Wall -Wextra -fsanitize=address,undefined
if /i "%~1"=="asan" set GNULINK=-fsanitize=address,undefined

if not exist build mkdir build
rd /s /q build\include 2>nul
rd /s /q build\lib 2>nul
rd /s /q build\example 2>nul
mkdir build\lib

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"

where cl >nul 2>nul
if not errorlevel 1 goto :probecl

if exist "%VSWHERE%" (
    for /f "usebackq delims=" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Auxiliary\Build\vcvars64.bat`) do call "%%i" >nul 2>nul
)

if exist "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" (
    call "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>nul
)

:probecl
where cl >nul 2>nul
if errorlevel 1 goto :probegxx

(echo int main^(^){return 0;})> "%TEMP%\dxp_probe.cpp"
cl /nologo "%TEMP%\dxp_probe.cpp" /Fe:"%TEMP%\dxp_probe.exe" /Fo:"%TEMP%\dxp_probe.obj" >nul 2>nul
if errorlevel 1 goto :probegxx
del /q "%TEMP%\dxp_probe.cpp" "%TEMP%\dxp_probe.exe" "%TEMP%\dxp_probe.obj" >nul 2>nul
goto :msvc

:probegxx
where g++ >nul 2>nul
if not errorlevel 1 goto :gxx

docker info >nul 2>nul
if not errorlevel 1 goto :docker

echo No usable compiler found.
echo Install the Windows SDK for MSVC, or MinGW g++, or start Docker Desktop.
exit /b 1

:msvc
del /q build\*.obj build\*.lib build\*.exe 2>nul
cl %MSVCFLAGS% /Fobuild\ %LIBSRC%
if errorlevel 1 exit /b 1
lib /nologo /OUT:build\lib\dxp.lib %LIBOBJMSVC%
if errorlevel 1 exit /b 1
cl %MSVCLINK% /Fobuild\ /Fe:build\demo.exe demo.cpp build\lib\dxp.lib
if errorlevel 1 exit /b 1
build\demo.exe
if errorlevel 1 exit /b 1
call :copy_package
cl %MSVCLINK% /Ibuild\include /Fobuild\example\example.obj /Fe:build\example\example.exe build\example\example.cpp build\lib\dxp.lib
if errorlevel 1 exit /b 1
build\example\example.exe
if errorlevel 1 exit /b 1
echo.
echo Library package ready: build\include, build\lib, build\example
exit /b 0

:gxx
del /q build\*.o build\*.a build\*.obj build\*.lib build\demo build\demo.exe 2>nul
for %%f in (%LIBNAMES%) do (
    g++ %GNUTOOLS% -c %%f.cpp -o build/%%f.o
    if errorlevel 1 exit /b 1
)
ar rcs build/lib/libdxp.a %LIBOBJGNU%
if errorlevel 1 exit /b 1
g++ %GNUTOOLS% demo.cpp build/lib/libdxp.a -o build/demo.exe %GNULINK% -lbcrypt
if errorlevel 1 exit /b 1
build\demo.exe
if errorlevel 1 exit /b 1
call :copy_package
g++ %GNUTOOLS% -Ibuild/include build/example/example.cpp build/lib/libdxp.a -o build/example/example.exe %GNULINK% -lbcrypt
if errorlevel 1 exit /b 1
build\example\example.exe
if errorlevel 1 exit /b 1
echo.
echo Library package ready: build\include, build\lib, build\example
exit /b 0

:docker
docker run --rm -v "%cd%:/src" -w /src --entrypoint sh vaayudrishti/backend:latest -c "set -e; rm -f build/*.o build/*.a build/demo build/demo.exe; for f in %LIBNAMES%; do g++ %GNUTOOLS% -c $f.cpp -o build/$f.o; done; ar rcs build/lib/libdxp.a %LIBOBJGNU%; g++ %GNUTOOLS% demo.cpp build/lib/libdxp.a -o build/demo %GNULINK%; ./build/demo; mkdir -p build/include build/example; cp %HEADERS% build/include/; cp example.cpp build/example/; g++ %GNUTOOLS% -Ibuild/include build/example/example.cpp build/lib/libdxp.a -o build/example/example.exe %GNULINK%; ./build/example/example.exe; echo; echo Library package ready: build/include, build/lib, build/example"
exit /b %errorlevel%

:copy_package
mkdir build\include 2>nul
mkdir build\example 2>nul
copy /y %HEADERS% build\include\ >nul
copy /y example.cpp build\example\ >nul
exit /b 0
