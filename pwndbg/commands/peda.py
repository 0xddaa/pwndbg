#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import sys

import gdb

import pwndbg.auxv
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.proc
from pwndbg.peda import *

peda = PEDA()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def getfile():
    peda.getfile()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def getpid():
    peda.getpid()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def searchmem(*arg):
    """
    Search for a pattern in memory; support regex search
    Usage:
        MYNAME pattern start end
        MYNAME pattern mapname
    """
    (pattern, start, end) = normalize_argv(arg, 3)
    (pattern, mapname) = normalize_argv(arg, 2)
    if pattern is None:
        raise TypeError

    pattern = arg[0]
    result = []
    if end is None and to_int(mapname):
        vmrange = peda.get_vmrange(mapname)
        if vmrange:
            (start, end, _, _) = vmrange

    if end is None:
        msg("Searching for %s in: %s ranges" % (repr(pattern), mapname))
        result = peda.searchmem_by_range(mapname, pattern)
    else:
        msg("Searching for %s in range: 0x%x - 0x%x" % (repr(pattern), start, end))
        result = peda.searchmem(start, end, pattern)

    text = peda.format_search_result(result)
    pager(text)

Alias("find", "searchmem") # override gdb find command
