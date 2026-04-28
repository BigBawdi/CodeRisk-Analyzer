This is the source code for the Operating Risk Code Analyzer, also known as ORCA. It is written in Python, and offers static analysis of C and C++ code using Cppcheck, Flawfinder, gcc compiler, and Coverity. All four tools must be installed prior to using this application.

HOW TO RUN: 
- Open up a Powershell terminal
- Navigate to CodeRisk-Analyzer
- Create a virtual environment with the following command: python -m venv .venv
- Activate the virtual enviroment: .\.venv\Scripts\Activate
    - If you recieve an error, set this command: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
- Pip install the requirements: pip install -r requirements.txt
- Finally, run the main function: cd frontend | python main.py

Guide to installing all tools:
1) Cppcheck
- Download from this link: https://github.com/cppcheck-opensource/cppcheck/releases/download/2.20.0/cppcheck-2.20.0-x64-Setup.msi
- Run installer for Cppcheck
- Add Cppcheck to Windows Path:
    - In your task bar search, search "environment variables" and click enter
    - In the Advanced tab, click "Environment Variables"
    - In System Variables, click "Path", then edit, then new
    - Add the following to path: C:\ProgramFiles\Cppcheck\
- Confirm successful download by checking in a terminal: cppcheck --version

2) Flawfinder
- Automatically installed when running application properly (included when pip install -r requirements.txt inside a virtual environment)

3) GCC Compiler
- Download from this link: https://github.com/msys2/msys2-installer/releases/download/2026-03-22/msys2-x86_64-20260322.exe
- Run the installer, and install to the default directory (C:\msys2)
- After installing, the MSYS2 terminal will run automatically. Enter the following command: pacman -Syu
- If the terminal closes after, reopen it and enter the following command: pacman -Su
- In the MSYS2 terminal, run the following command: pacman -S mingw-w64-ucrt-x86_64-gcc
- Add GCC to Windows path:
  - In your task bar search, search "environment variables" and click enter
  - In the Advanced tab, click "Environment Variables"
  - In System Variables, click "Path", then edit, then new
  - Add the following to path: C:\msys64\ucrt64\bin
- Confirm successful download by checking in a terminal: gcc --version

4) Coverity
- Coverity unfortunately will not work for this project. Coverity is closed-source, and requires a premium to make it work in the command line. Coverity Scan is free, but uses cloud based static analysis instead of command line analysis. Since this project utilizes open-source command line binaries, we were unfortunately unable to make it work with our project.
