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
from pwndbg.pwngdb import *

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
