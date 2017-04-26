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
