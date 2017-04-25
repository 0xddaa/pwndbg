#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Pwngdb by angenboy

https://github.com/scwuaptx/Pwngdb
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import copy
import os
import re
import subprocess

import gdb

import pwndbg.commands
import pwndbg.arch
import pwndbg.proc
import pwndbg.search
from pwndbg.pwngdb import *

@pwndbg.commands.Command
def at(*arg):
    """Automatically attach process by filename."""
    processname = arg[0] if len(arg) > 0 else pwndbg.proc.exe
    try :
        print('attaching to {} ...'.format(processname))
        pidlist = subprocess.check_output('pidof $(basename {})'.format(processname), shell=True).decode('utf8').split()
        gdb.execute("attach " + pidlist[0])
        getheapbase()
        libcbase()
        codeaddr()
        ldbase()
    except :
        print("no such process")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def libc():
    """ Get libc base """
    print("\033[34m" + "libc : " + "\033[37m" + hex(libcbase()))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def heap():
    """ Get heapbase """
    heapbase = getheapbase()
    if heapbase :
        print("\033[34m" + "heapbase : " + "\033[37m" + hex(heapbase))
    else :
        print("heap not found")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ld():
    """ Get ld.so base """
    print("\033[34m" + "ld : " + "\033[37m" + hex(ldbase()))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def codebase():
    """ Get text base """
    codebs = codeaddr()[0]
    print("\033[34m" + "codebase : " + "\033[37m" + hex(codebs))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def tls():
    """ Get tls base """
    tlsaddr = gettls()
    if tlsaddr != -1:
        print("\033[34m" + "tls : " + "\033[37m" + hex(tlsaddr))
    else:
        print("cannot get tls")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def canary():
    """ Get canary value """
    canary = getcanary()
    if canary != -1:
        print("\033[34m" + "canary : " + "\033[37m" + hex(canary))
    else:
        print("cannot get cannary")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def off(*arg) :
    """ Calculate the offset of libc """
    if len(arg) < 1:
        print("no symbol given")
        return

    sym = arg[0]
    symaddr = getoff(sym)
    if symaddr != -1 :
        if type(sym) is int :
            print("\033[34m" + hex(sym)  + " : " + "\033[37m" + hex(symaddr))
        else :
            print("\033[34m" + sym  + " : " + "\033[37m" + hex(symaddr))
    else :
        print("symbol not found")

@pwndbg.commands.Command
def got():
    """ Print the got table """
    processname = pwndbg.proc.exe
    if not processname :
        print("no current process or executable file specified")
        return

    cmd = "objdump -R {} {}".format("--demangle" if iscplus() else "", processname)
    print(subprocess.check_output(cmd, shell=True)[:-2].decode("utf8").strip())

@pwndbg.commands.Command
def dyn():
    """ Print dynamic section """
    processname = pwndbg.proc.exe
    if not processname:
        print("no current process or executable file specified")
        return

    print(subprocess.check_output("readelf -d {}".format(processname), shell=True).decode("utf8").strip())

@pwndbg.commands.Command
def findcall(symbol):
    """ Find some function call """
    call = searchcall(symbol)
    print(call) if call != -1 else print("symbol not found")

@pwndbg.commands.Command
def bcall(symbol):
    """ Set the breakpoint at some function call """
    call = searchcall(symbol)
    if call == -1:
        print("symbol not found")
        return

    codebase = codeaddr()[0] if ispie() else 0
    for callbase in call.split('\n'):
        addr = int(callbase.split(':')[0],16) + codebase
        gdb.execute("b *{}".format(hex(addr)))
