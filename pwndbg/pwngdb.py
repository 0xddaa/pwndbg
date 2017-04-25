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

import re

import gdb

import pwndbg.proc

def procmap():
    data = gdb.execute("info proc exe", to_string = True)
    pid = re.search("process.*", data)
    if pid :
        pid = pid.group().split()[1]
        with open("/proc/{}/maps".format(pid), "r") as maps:
            return maps.read()
    else :
        return "error"

def libcbase():
    data = re.search(".*libc.*\.so", procmap())
    if data :
        libcaddr = data.group().split("-")[0]
        gdb.execute("set $libc={}".format(hex(int(libcaddr, 16))))
        return int(libcaddr, 16)
    else :
        return 0

def getheapbase():
    data = re.search(".*heap\]", procmap())
    if data :
        heapbase = data.group().split("-")[0]
        gdb.execute("set $heap={}".format(hex(int(heapbase, 16))))
        return int(heapbase, 16)
    else :
        return 0

def ldbase():
    data = re.search(".*ld.*\.so", procmap())
    if data :
        ldaddr = data.group().split("-")[0]
        gdb.execute("set $ld=%s".format(hex(int(ldaddr, 16))))
        return int(ldaddr, 16)
    else :
        return 0

def codeaddr(): # ret (start, end)
    pat = ".*" + pwndbg.proc.exe
    data = re.findall(pat, procmap())
    if data :
        codebaseaddr = data[0].split("-")[0]
        codeend = data[0].split("-")[1].split()[0]
        gdb.execute("set $code={}".format(hex(int(codebaseaddr, 16))))
        return (int(codebaseaddr, 16), int(codeend, 16))
    else :
        return (0, 0)
