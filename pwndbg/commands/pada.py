#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Custom gdb command by ddaa
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import subprocess

import gdb

import pwndbg.commands


@pwndbg.commands.Command
def auto_attach(*arg):
    """Automatically attach process by filename."""
    processname = arg[0] if len(arg) > 0 else pwndbg.proc.exe
    try :
        print('Attaching to {} ...'.format(processname))
        pidlist = subprocess.check_output('pidof $(basename {})'.format(processname), shell=True).decode('utf8').split()
        gdb.execute("attach " + pidlist[0])
    except :
        print( "No such process" )
