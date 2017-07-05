#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Custom gdb command by ddaa
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import socket
import sys

import gdb

import pwndbg.commands

IDA_HOST = '10.113.208.101'
PORT = 56746
TMPDIR = '/tmp/iddaa'

def connect_ida():
    if not os.path.exists(TMPDIR):
        os.mkdir(TMPDIR)
    try:
        sock = socket.create_connection((IDA_HOST, PORT), timeout=3)
        return sock
    except socket.error as err:
        sys.stderr.write("[ERROR] {}\n".format(err))
        return None

def send(sock, buf):
    if sys.version_info < (3, 0):
        sock.send(buf)
    else:
        sock.send(bytes(buf, 'UTF-8'))

def recv(sock, raw=False):
    buf = bytes()
    while True:
        tmp = sock.recv(4096)
        buf += tmp
        if not tmp:
            break
    if raw:
        return buf
    else:
        return buf if sys.version_info < (3, 0) else buf.decode()

@pwndbg.commands.Command
def get_ida_symbols():
    sock = connect_ida()
    if not sock: return

    send(sock, 'GETSYM')
    buf = recv(sock, True)

    filename = '{}/{}'.format(TMPDIR, pwndbg.proc.exe.split('/')[-1])
    with open(filename, 'wb') as f:
        f.write(buf)

    if os.path.exists(filename):
        gdb.execute('file {}'.format(filename))
    else:
        print('Can\'t not receive ida symfile.')
