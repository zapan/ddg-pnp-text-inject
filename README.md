Densha de Go! Plug & Play Text Injector
=================================

This is a quick and dirty program to replace the text embedded in DDG Plug & Play ELF executable.


Requirements
------------
Requires [GNU Arm Embedded Toolchain Downloads](https://developer.arm.com/downloads/-/gnu-rm)

Requires [pyelftools](https://pypi.org/project/pyelftools/)

Requires macOS or Linux system. Tested only on macOS.

Usage
------------
    > python ddg-pnp-text-inject.py <elf_source> <eld_patched> <lect_path> <menu_path>
