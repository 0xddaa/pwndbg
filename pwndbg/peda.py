#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
PEDA - Python Exploit Development Assistance for GDB

https://github.com/longld/peda
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import re
import os
import codecs
import tempfile
import inspect
import six
import sys
import struct
import string

import gdb

OPTIONS = {
    "badchars"  : ("", "bad characters to be filtered in payload/output, e.g: '\\x0a\\x00'"),
    "pattern"   : (1, "pattern type, 0 = basic, 1 = extended, 2 = maximum"),
    "p_charset" : ("", "custom charset for pattern_create"),
    "indent"    : (4, "number of ident spaces for output python payload, e.g: 0|4|8"),
    "ansicolor" : ("on", "enable/disable colorized output, e.g: on|off"),
    "pagesize"  : (25, "number of lines to display per page, 0 = disable paging"),
    "session"   : ("peda-session-#FILENAME#.txt", "target file to save peda session"),
    "tracedepth": (0, "max depth for calls/instructions tracing, 0 means no limit"),
    "tracelog"  : ("peda-trace-#FILENAME#.txt", "target file to save tracecall output"),
    "crashlog"  : ("peda-crashdump-#FILENAME#.txt", "target file to save crash dump of fuzzing"),
    "snapshot"  : ("peda-snapshot-#FILENAME#.raw", "target file to save crash dump of fuzzing"),
    "autosave"  : ("on", "auto saving peda session, e.g: on|off"),
    "payload"   : ("peda-payload-#FILENAME#.txt", "target file to save output of payload command"),
    "context"   : ("register,code,stack", "context display setting, e.g: register, code, stack, all"),
    "verbose"   : ("off", "show detail execution of commands, e.g: on|off"),
    "debug"     : ("off", "show detail error of peda commands, e.g: on|off"),
    "_teefd"    : ("", "internal use only for tracelog/crashlog writing")
}

## END OF SETTINGS ##

class Option(object):
    """
    Class to access global options of PEDA commands and functions
    TODO: save/load option to/from file
    """
    options = OPTIONS.copy()
    def __init__(self):
        """option format: name = (value, 'help message')"""
        pass


    @staticmethod
    def reset():
        """reset to default options"""
        Option.options = OPTIONS.copy()
        return True

    @staticmethod
    def show(name=""):
        """display options"""
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][0]
        return result

    @staticmethod
    def get(name):
        """get option"""
        if name in Option.options:
            return Option.options[name][0]
        else:
            return None

    @staticmethod
    def set(name, value):
        """set option"""
        if name in Option.options:
            Option.options[name] = (value, Option.options[name][1])
            return True
        else:
            return False

    @staticmethod
    def help(name=""):
        """display help info of options"""
        result = {}
        for opt in Option.options:
            if name in opt and not opt.startswith("_"):
                result[opt] = Option.options[opt][1]
        return result

# http://wiki.python.org/moin/PythonDecoratorLibrary#Memoize
# http://stackoverflow.com/questions/8856164/class-decorator-decorating-method-in-python
class memoized(object):
    """
    Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).
    """
    def __init__(self, func):
        self.func = func
        self.instance = None # bind with instance class of decorated method
        self.cache = {}
        self.__doc__ = inspect.getdoc(self.func)

    def __call__(self, *args, **kwargs):
        try:
            return self.cache[(self.func, self.instance, args) + tuple(kwargs.items())]
        except KeyError:
            if self.instance is None:
                value = self.func(*args, **kwargs)
            else:
                value = self.func(self.instance, *args, **kwargs)
            self.cache[(self.func, self.instance, args) + tuple(kwargs.items())] = value
            return value
        except TypeError:
            # uncachable -- for instance, passing a list as an argument.
            # Better to not cache than to blow up entirely.
            if self.instance is None:
                return self.func(*args, **kwargs)
            else:
                return self.func(self.instance, *args, **kwargs)

    def __repr__(self):
        """Return the function's docstring."""
        return self.__doc__

    def __get__(self, obj, objtype):
        """Support instance methods."""
        if obj is None:
            return self
        else:
            self.instance = obj
            return self

    def _reset(self):
        """Reset the cache"""
        # Make list to prevent modifying dictionary while iterating
        for cached in list(self.cache.keys()):
            if cached[0] == self.func and cached[1] == self.instance:
                del self.cache[cached]

def reset_cache(module=None):
    """
    Reset memoized caches of an instance/module
    """
    if module is None:
        module = sys.modules['__main__']

    for m in dir(module):
        m = getattr(module, m)
        if isinstance(m, memoized):
            m._reset()
        else:
            for f in dir(m):
                f = getattr(m, f)
                if isinstance(f, memoized):
                    f._reset()

    return True

def tmpfile(pref="peda-", is_binary_file=False):
    """Create and return a temporary file with custom prefix"""

    mode = 'w+b' if is_binary_file else 'w+'
    return tempfile.NamedTemporaryFile(mode=mode, prefix=pref)

def colorize(text, color=None, attrib=None):
    """
    Colorize text using ansicolor
    ref: https://github.com/hellman/libcolors/blob/master/libcolors.py
    """
    # ansicolor definitions
    COLORS = {"black": "30", "red": "31", "green": "32", "yellow": "33",
                "blue": "34", "purple": "35", "cyan": "36", "white": "37"}
    CATTRS = {"regular": "0", "bold": "1", "underline": "4", "strike": "9",
                "light": "1", "dark": "2", "invert": "7"}

    CPRE = '\033['
    CSUF = '\033[0m'

    if Option.get("ansicolor") != "on":
        return text

    ccode = ""
    if attrib:
        for attr in attrib.lower().split():
            attr = attr.strip(",+|")
            if attr in CATTRS:
                ccode += ";" + CATTRS[attr]
    if color in COLORS:
        ccode += ";" + COLORS[color]
    return CPRE + ccode + "m" + text + CSUF

def green(text, attrib=None):
    """Wrapper for colorize(text, 'green')"""
    return colorize(text, "green", attrib)

def red(text, attrib=None):
    """Wrapper for colorize(text, 'red')"""
    return colorize(text, "red", attrib)

def yellow(text, attrib=None):
    """Wrapper for colorize(text, 'yellow')"""
    return colorize(text, "yellow", attrib)

def blue(text, attrib=None):
    """Wrapper for colorize(text, 'blue')"""
    return colorize(text, "blue", attrib)

class message(object):
    """
    Generic pretty printer with redirection.
    It also suports buffering using bufferize() and flush().
    """

    def __init__(self):
        self.out = sys.stdout
        self.buffering = 0

    def bufferize(self, f=None):
        """Activate message's bufferization, can also be used as a decorater."""

        if f != None:
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                self.bufferize()
                f(*args, **kwargs)
                self.flush()
            return wrapper

        # If we are still using stdio we need to change it.
        if not self.buffering:
            self.out = StringIO()
        self.buffering += 1

    def flush(self):
        if not self.buffering:
            raise ValueError("Tried to flush a message that is not bufferising.")
        self.buffering -= 1

        # We only need to flush if this is the lowest recursion level.
        if not self.buffering:
            self.out.flush()
            sys.stdout.write(self.out.getvalue())
            self.out = sys.stdout

    def __call__(self, text, color=None, attrib=None, teefd=None):
        if not teefd:
            teefd = Option.get("_teefd")

        if isinstance(text, six.string_types) and "\x00" not in text:
            print(colorize(text, color, attrib), file=self.out)
            if teefd:
                print(colorize(text, color, attrib), file=teefd)
        else:
            pprint.pprint(text, self.out)
            if teefd:
                pprint.pprint(text, teefd)

msg = message()

def warning_msg(text):
    """Colorize warning message with prefix"""
    msg(colorize("Warning: " + str(text), "yellow"))

def error_msg(text):
    """Colorize error message with prefix"""
    msg(colorize("Error: " + str(text), "red"))

def debug_msg(text, prefix="Debug"):
    """Colorize debug message with prefix"""
    msg(colorize("%s: %s" % (prefix, str(text)), "cyan"))

def trim(docstring):
    """
    Handle docstring indentation, ref: PEP257
    """
    if not docstring:
        return ''
    # Convert tabs to spaces (following the normal Python rules)
    # and split into a list of lines:
    lines = docstring.expandtabs().splitlines()
    # Determine minimum indentation (first line doesn't count):
    max_indent = sys.maxsize
    indent = max_indent
    for line in lines[1:]:
        stripped = line.lstrip()
        if stripped:
            indent = min(indent, len(line) - len(stripped))
    # Remove indentation (first line is special):
    trimmed = [lines[0].strip()]
    if indent < max_indent:
        for line in lines[1:]:
            trimmed.append(line[indent:].rstrip())
    # Strip off trailing and leading blank lines:
    while trimmed and not trimmed[-1]:
        trimmed.pop()
    while trimmed and not trimmed[0]:
        trimmed.pop(0)
    # Return a single string:
    return '\n'.join(trimmed)

def pager(text, pagesize=None):
    """
    Paging output, mimic external command less/more
    """
    if not pagesize:
        pagesize = Option.get("pagesize")

    if pagesize <= 0:
        msg(text)
        return

    i = 1
    text = text.splitlines()
    l = len(text)

    for line in text:
        msg(line)
        if i % pagesize == 0:
            ans = input("--More--(%d/%d)" % (i, l))
            if ans.lower().strip() == "q":
                break
        i += 1

    return

def execute_external_command(command, cmd_input=None):
    """
    Execute external command and capture its output

    Args:
        - command (String)

    Returns:
        - output of command (String)
    """
    result = ""
    P = Popen([command], stdout=PIPE, stdin=PIPE, stderr=PIPE, shell=True)
    (result, err) = P.communicate(cmd_input)
    if err and Option.get("debug") == "on":
        warning_msg(err)

    return decode_string_escape(result)

def is_printable(text, printables=""):
    """
    Check if a string is printable
    """
    if six.PY3 and isinstance(text, six.string_types):
        text = six.b(text)
    return set(text) - set(six.b(string.printable) + six.b(printables)) == set()

def is_math_exp(str):
    """
    Check if a string is a math exprssion
    """
    charset = set("0123456789abcdefx+-*/%^")
    opers = set("+-*/%^")
    exp = set(str.lower())
    return (exp & opers != set()) and (exp - charset == set())

def normalize_argv(args, size=0):
    """
    Normalize argv to list with predefined length
    """
    args = list(args)
    for (idx, val) in enumerate(args):
        if to_int(val) is not None:
            args[idx] = to_int(val)
        if size and idx == size:
            return args[:idx]

    if size == 0:
        return args
    for i in range(len(args), size):
        args += [None]
    return args

def to_hexstr(str_):
    """
    Convert a binary string to hex escape format
    """
    return "".join(["\\x%02x" % ord(i) for i in bytes_iterator(str_)])

def to_hex(num):
    """
    Convert a number to hex format
    """
    if num < 0:
        return "-0x%x" % (-num)
    else:
        return "0x%x" % num

def to_address(num):
    """
    Convert a number to address format in hex
    """
    if num < 0:
        return to_hex(num)
    if num > 0xffffffff: # 64 bit
        return "0x%016x" % num
    else:
        return "0x%08x" % num

def to_int(val):
    """
    Convert a string to int number
    """
    try:
        return int(str(val), 0)
    except:
        return None

def str2hex(str):
    """
    Convert a string to hex encoded format
    """
    result = codecs.encode(str, 'hex')
    return result

def hex2str(hexnum, intsize=4):
    """
    Convert a number in hex format to string
    """
    if not isinstance(hexnum, six.string_types):
        nbits = intsize * 8
        hexnum = "0x%x" % ((hexnum + (1 << nbits)) % (1 << nbits))
    s = hexnum[2:]
    if len(s) % 2 != 0:
        s = "0" + s
    result = codecs.decode(s, 'hex')[::-1]
    return result

def int2hexstr(num, intsize=4):
    """
    Convert a number to hexified string
    """
    if intsize == 8:
        if num < 0:
            result = struct.pack("<q", num)
        else:
            result = struct.pack("<Q", num)
    else:
        if num < 0:
            result = struct.pack("<l", num)
        else:
            result = struct.pack("<L", num)
    return result

def list2hexstr(intlist, intsize=4):
    """
    Convert a list of number/string to hexified string
    """
    result = ""
    for value in intlist:
        if isinstance(value, str):
            result += value
        else:
            result += int2hexstr(value, intsize)
    return result

def str2intlist(data, intsize=4):
    """
    Convert a string to list of int
    """
    result = []
    data = decode_string_escape(data)[::-1]
    l = len(data)
    data = ("\x00" * (intsize - l%intsize) + data) if l%intsize != 0 else data
    for i in range(0, l, intsize):
        if intsize == 8:
            val = struct.unpack(">Q", data[i:i+intsize])[0]
        else:
            val = struct.unpack(">L", data[i:i+intsize])[0]
        result = [val] + result
    return result

@memoized
def check_badchars(data, chars=None):
    """
    Check an address or a value if it contains badchars
    """
    if to_int(data) is None:
        to_search = data
    else:
        data = to_hex(to_int(data))[2:]
        if len(data) % 2 != 0:
            data = "0" + data
        to_search = codecs.decode(data, 'hex')

    if not chars:
        chars = Option.get("badchars")

    if chars:
        for c in chars:
            if c in to_search:
                return True
    return False

@memoized
def format_address(addr, type):
    """Colorize an address"""
    colorcodes = {
        "data": "blue",
        "code": "red",
        "rodata": "green",
        "value": None
    }
    return colorize(addr, colorcodes[type])

@memoized
def format_reference_chain(chain):
    """
    Colorize a chain of references
    """
    v = t = vn = None
    text = ""
    if not chain:
        text += "Cannot access memory address"
    else:
        first = True
        for (v, t, vn) in chain:
            if t != "value":
                text += "%s%s " % ("--> " if not first else "", format_address(v, t))
            else:
                text += "%s%s " % ("--> " if not first else "", v)
            first = False

        if vn:
            text += "(%s)" % vn
        else:
            if v != "0x0":
                s = hex2str(v)
                if is_printable(s, "\x00"):
                    text += "(%s)" % string_repr(s.split(b"\x00")[0])
    return text

# vulnerable C functions, source: rats/flawfinder
VULN_FUNCTIONS = [
    "exec", "system", "gets", "popen", "getenv", "strcpy", "strncpy", "strcat", "strncat",
    "memcpy", "bcopy", "printf", "sprintf", "snprintf", "scanf",  "getchar", "getc", "read",
    "recv", "tmp", "temp"
]
@memoized
def format_disasm_code(code, nearby=None):
    """
    Format output of disassemble command with colors to highlight:
        - dangerous functions (rats/flawfinder)
        - branching: jmp, call, ret
        - testing: cmp, test

    Args:
        - code: input asm code (String)
        - nearby: address for nearby style format (Int)

    Returns:
        - colorized text code (String)
    """
    colorcodes = {
        "cmp": "red",
        "test": "red",
        "call": "green",
        "j": "yellow", # jump
        "ret": "blue",
    }
    result = ""

    if not code:
        return result

    if to_int(nearby) is not None:
        target = to_int(nearby)
    else:
        target = 0

    for line in code.splitlines():
        if ":" not in line: # not an assembly line
            result += line + "\n"
        else:
            color = style = None
            m = re.search(".*(0x[^ ]*).*:\s*([^ ]*)", line)
            if not m: # failed to parse
                result += line + "\n"
                continue
            addr, opcode = to_int(m.group(1)), m.group(2)
            for c in colorcodes:
                if c in opcode:
                    color = colorcodes[c]
                    if c == "call":
                        for f in VULN_FUNCTIONS:
                            if f in line.split(":\t", 1)[-1]:
                                style = "bold, underline"
                                color = "red"
                                break
                    break

            prefix = line.split(":\t")[0]
            addr = re.search("(0x[^\s]*)", prefix)
            if addr:
                addr = to_int(addr.group(1))
            else:
                addr = -1
            line = "\t" + line.split(":\t", 1)[-1]
            if addr < target:
                style = "dark"
            elif addr == target:
                style = "bold"
                color = "green"

            code = colorize(line.split(";")[0], color, style)
            if ";" in line:
                comment = colorize(";" + line.split(";", 1)[1], color, "dark")
            else:
                comment = ""
            line = "%s:%s%s" % (prefix, code, comment)
            result += line + "\n"

    return result.rstrip()

def cyclic_pattern_charset(charset_type=None):
    """
    Generate charset for cyclic pattern

    Args:
        - charset_type: charset type
            0: basic (0-9A-za-z)
            1: extended (default)
            2: maximum (almost printable chars)

    Returns:
        - list of charset
    """

    charset = []
    charset += ["ABCDEFGHIJKLMNOPQRSTUVWXYZ"] # string.uppercase
    charset += ["abcdefghijklmnopqrstuvwxyz"] # string.lowercase
    charset += ["0123456789"] # string.digits

    if not charset_type:
        charset_type = Option.get("pattern")

    if charset_type == 1: # extended type
        charset[1] = "%$-;" + re.sub("[sn]", "", charset[1])
        charset[2] = "sn()" + charset[2]

    if charset_type == 2: # maximum type
        charset += ['!"#$%&\()*+,-./:;<=>?@[]^_{|}~'] # string.punctuation

    mixed_charset = mixed = ''
    k = 0
    while True:
        for i in range(0, len(charset)): mixed += charset[i][k:k+1]
        if not mixed: break
        mixed_charset += mixed
        mixed = ''
        k+=1

    return mixed_charset

def de_bruijn(charset, n, maxlen):
    """
    Generate the De Bruijn Sequence up to `maxlen` characters for the charset `charset`
    and subsequences of length `n`.
    Algorithm modified from wikipedia http://en.wikipedia.org/wiki/De_Bruijn_sequence
    """
    k = len(charset)
    a = [0] * k * n
    sequence = []
    def db(t, p):
        if len(sequence) == maxlen:
            return

        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    sequence.append(charset[a[j]])
                    if len(sequence) == maxlen:
                        return
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1,1)
    return ''.join(sequence)

@memoized
def cyclic_pattern(size=None, start=None, charset_type=None):
    """
    Generate a cyclic pattern

    Args:
        - size: size of generated pattern (Int)
        - start: the start offset of the generated pattern (Int)
        - charset_type: charset type
            0: basic (0-9A-za-z)
            1: extended (default)
            2: maximum (almost printable chars)

    Returns:
        - pattern text (byte string) (str in Python 2; bytes in Python 3)
    """
    charset = Option.get("p_charset")
    if not charset:
        charset = cyclic_pattern_charset(charset)
    else:
        charset = ''.join(set(charset))

    if start is None:
        start = 0
    if size is None:
        size = 0x10000

    size += start

    pattern = de_bruijn(charset, 3, size)

    return pattern[start:size].encode('utf-8')

@memoized
def cyclic_pattern_offset(value):
    """
    Search a value if it is a part of cyclic pattern

    Args:
        - value: value to search for (String/Int)

    Returns:
        - offset in pattern if found
    """
    pattern = cyclic_pattern()
    if to_int(value) is None:
        search = value.encode('utf-8')
    else:
        search = hex2str(to_int(value))

    pos = pattern.find(search)
    return pos if pos != -1 else None

def cyclic_pattern_search(buf):
    """
    Search all cyclic pattern pieces in a buffer

    Args:
        - buf: buffer to search for (String)

    Returns:
        - list of tuple (buffer_offset, pattern_len, pattern_offset)
    """
    result = []
    pattern = cyclic_pattern()

    p = re.compile(b"[" + re.escape(to_binary_string(cyclic_pattern_charset())) + b"]{4,}")
    found = p.finditer(buf)
    found = list(found)
    for m in found:
        s = buf[m.start():m.end()]
        i = pattern.find(s)
        k = 0
        while i == -1 and len(s) > 4:
            s = s[1:]
            k += 1
            i = pattern.find(s)
        if i != -1:
            result += [(m.start()+k, len(s), i)]

    return result


def _decode_string_escape_py2(str_):
    """
    Python2 string escape

    Do not use directly, instead use decode_string.
    """
    return str_.decode('string_escape')


def _decode_string_escape_py3(str_):
    """
    Python3 string escape

    Do not use directly, instead use decode_string.
    """

    # Based on: http://stackoverflow.com/a/4020824
    return codecs.decode(str_, "unicode_escape")


def decode_string_escape(str_):
    """Generic Python string escape"""
    raise Exception('Should be overriden')


def bytes_iterator(bytes_):
    """
    Returns iterator over a bytestring. In Python 2, this is just a str. In
    Python 3, this is a bytes.

    Wrap this around a bytestring when you need to iterate to be compatible
    with Python 2 and Python 3.
    """
    raise Exception('Should be overriden')


def _bytes_iterator_py2(bytes_):
    """
    Returns iterator over a bytestring in Python 2.

    Do not call directly, use bytes_iterator instead
    """
    for b in bytes_:
        yield b


def _bytes_iterator_py3(bytes_):
    """
    Returns iterator over a bytestring in Python 3.

    Do not call directly, use bytes_iterator instead
    """
    for b in bytes_:
        yield bytes([b])


def bytes_chr(i):
    """
    Returns a byte string  of length 1 whose ordinal value is i. In Python 2,
    this is just a str. In Python 3, this is a bytes.

    Use this instead of chr to be compatible with Python 2 and Python 3.
    """
    raise Exception('Should be overriden')


def _bytes_chr_py2(i):
    """
    Returns a byte string  of length 1 whose ordinal value is i in Python 2.

    Do not call directly, use bytes_chr instead.
    """
    return chr(i)


def _bytes_chr_py3(i):
    """
    Returns a byte string  of length 1 whose ordinal value is i in Python 3.

    Do not call directly, use bytes_chr instead.
    """
    return bytes([i])


def to_binary_string(text):
    """
    Converts a string to a binary string if it is not already one. Returns a str
    in Python 2 and a bytes in Python3.

    Use this instead of six.b when the text may already be a binary type
    """
    raise Exception('Should be overriden')


def _to_binary_string_py2(text):
    """
    Converts a string to a binary string if it is not already one. Returns a str
    in Python 2 and a bytes in Python3.

    Do not use directly, use to_binary_string instead.
    """
    return str(text)


def _to_binary_string_py3(text):
    """
    Converts a string to a binary string if it is not already one. Returns a str
    in Python 2 and a bytes in Python3.

    Do not use directly, use to_binary_string instead.
    """
    if isinstance(text, six.binary_type):
        return text
    elif isinstance(text, six.string_types):
        return six.b(text)
    else:
        raise Exception('only takes string types')


# Select functions based on Python version
if six.PY2:
    decode_string_escape = _decode_string_escape_py2
    bytes_iterator = _bytes_iterator_py2
    bytes_chr = _bytes_chr_py2
    to_binary_string = _to_binary_string_py2
elif six.PY3:
    decode_string_escape = _decode_string_escape_py3
    bytes_iterator = _bytes_iterator_py3
    bytes_chr = _bytes_chr_py3
    to_binary_string = _to_binary_string_py3
else:
    raise Exception("Could not identify Python major version")


def dbg_print_vars(*args):
    """Prints name and repr of each arg on a separate line"""
    import inspect
    parent_locals = inspect.currentframe().f_back.f_locals
    maps = []
    for arg in args:
        for name, value in parent_locals.items():
            if id(arg) == id(value):
                maps.append((name, repr(value)))
                break
    print('\n'.join(name + '=' + value for name, value in maps))


def string_repr(text, show_quotes=True):
    """
    Prints the repr of a string. Eliminates the leading 'b' in the repr in
    Python 3.

    Optionally can show or include quotes.
    """
    if six.PY3 and isinstance(text, six.binary_type):
        # Skip leading 'b' at the beginning of repr
        output = repr(text)[1:]
    else:
        output = repr(text)

    if show_quotes:
        return output
    else:
        return output[1:-1]

class PEDA(object):
    """
    Class for actual functions of PEDA commands
    """
    def __init__(self):
        self.SAVED_COMMANDS = {} # saved GDB user's commands


    ####################################
    #   GDB Interaction / Misc Utils   #
    ####################################
    def execute(self, gdb_command):
        """
        Wrapper for gdb.execute, catch the exception so it will not stop python script

        Args:
            - gdb_command (String)

        Returns:
            - True if execution succeed (Bool)
        """
        try:
            gdb.execute(gdb_command)
            return True
        except Exception as e:
            if Option.get("debug") == "on":
                msg('Exception (%s): %s' % (gdb_command, e), "red")
                traceback.print_exc()
            return False

    def execute_redirect(self, gdb_command, silent=False):
        """
        Execute a gdb command and capture its output

        Args:
            - gdb_command (String)
            - silent: discard command's output, redirect to /dev/null (Bool)

        Returns:
            - output of command (String)
        """
        result = None
        #init redirection
        if silent:
            logfd = open(os.path.devnull, "r+")
        else:
            logfd = tmpfile()
        logname = logfd.name
        gdb.execute('set logging off') # prevent nested call
        gdb.execute('set height 0') # disable paging
        gdb.execute('set logging file %s' % logname)
        gdb.execute('set logging overwrite on')
        gdb.execute('set logging redirect on')
        gdb.execute('set logging on')
        try:
            gdb.execute(gdb_command)
            gdb.flush()
            gdb.execute('set logging off')
            if not silent:
                logfd.flush()
                result = logfd.read()
            logfd.close()
        except Exception as e:
            gdb.execute('set logging off') #to be sure
            if Option.get("debug") == "on":
                msg('Exception (%s): %s' % (gdb_command, e), "red")
                traceback.print_exc()
            logfd.close()
        if Option.get("verbose") == "on":
            msg(result)
        return result

    def parse_and_eval(self, exp):
        """
        Work around implementation for gdb.parse_and_eval with enhancements

        Args:
            - exp: expression to evaluate (String)

        Returns:
            - value of expression
        """

        regs = sum(REGISTERS.values(), [])
        for r in regs:
            if "$"+r not in exp and "e"+r not in exp and "r"+r not in exp:
                exp = exp.replace(r, "$%s" % r)

        p = re.compile("(.*)\[(.*)\]") # DWORD PTR [esi+eax*1]
        matches = p.search(exp)
        if not matches:
            p = re.compile("(.*).s:(0x.*)") # DWORD PTR ds:0xdeadbeef
            matches = p.search(exp)

        if matches:
            mod = "w"
            if "BYTE" in matches.group(1):
                mod = "b"
            elif "QWORD" in matches.group(1):
                mod = "g"
            elif "DWORD" in matches.group(1):
                mod = "w"
            elif "WORD" in matches.group(1):
                mod = "h"

            out = self.execute_redirect("x/%sx %s" % (mod, matches.group(2)))
            if not out:
                return None
            else:
                return out.split(":\t")[-1].strip()

        else:
            out = self.execute_redirect("print %s" % exp)
        if not out:
            return None
        else:
            out = gdb.history(0).__str__()
            out = out.encode('ascii', 'ignore')
            out = decode_string_escape(out)
            return out.strip()

    def string_to_argv(self, str):
        """
        Convert a string to argv list, pre-processing register and variable values

        Args:
            - str: input string (String)

        Returns:
            - argv list (List)
        """
        try:
            str = str.encode('ascii', 'ignore')
        except:
            pass
        str = decode_string_escape(str)
        args = shlex.split(str)
        # need more processing here
        for idx, a in enumerate(args):
            a = a.strip(",")
            if a.startswith("$"): # try to get register/variable value
                v = self.parse_and_eval(a)
                if v != None and v != "void":
                    if v.startswith("0x"): # int
                        args[idx] = v.split()[0] # workaround for 0xdeadbeef <symbol+x>
                    else: # string, complex data
                        args[idx] = v
            elif a.startswith("+"): # relative value to prev arg
                adder = to_int(self.parse_and_eval(a[1:]))
                if adder is not None:
                    args[idx] = "%s" % to_hex(to_int(args[idx-1]) + adder)
            elif is_math_exp(a):
                try:
                    v = eval("%s" % a)
                    # XXX hack to avoid builtin functions/types
                    if not isinstance(v, six.string_types + six.integer_types):
                        continue
                    args[idx] = "%s" % (to_hex(v) if to_int(v) != None else v)
                except:
                    pass
        if Option.get("verbose") == "on":
            msg(args)
        return args


    ################################
    #   GDB User-Defined Helpers   #
    ################################
    def save_user_command(self, cmd):
        """
        Save user-defined command and deactivate it

        Args:
            - cmd: user-defined command (String)

        Returns:
            - True if success to save (Bool)
        """
        commands = self.execute_redirect("show user %s" % cmd)
        if not commands:
            return False

        commands = "\n".join(commands.splitlines()[1:])
        commands = "define %s\n" % cmd + commands + "end\n"
        self.SAVED_COMMANDS[cmd] = commands
        tmp = tmpfile()
        tmp.write("define %s\nend\n" % cmd)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    def define_user_command(self, cmd, code):
        """
        Define a user-defined command, overwrite the old content

        Args:
            - cmd: user-defined command (String)
            - code: gdb script code to append (String)

        Returns:
            - True if success to define (Bool)
        """
        commands = "define %s\n" % cmd + code + "\nend\n"
        tmp = tmpfile(is_binary_file=False)
        tmp.write(commands)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    def append_user_command(self, cmd, code):
        """
        Append code to a user-defined command, define new command if not exist

        Args:
            - cmd: user-defined command (String)
            - code: gdb script code to append (String)

        Returns:
            - True if success to append (Bool)
        """

        commands = self.execute_redirect("show user %s" % cmd)
        if not commands:
            return self.define_user_command(cmd, code)
        # else
        commands = "\n".join(commands.splitlines()[1:])
        if code in commands:
            return True

        commands = "define %s\n" % cmd + commands + code + "\nend\n"
        tmp = tmpfile()
        tmp.write(commands)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    def restore_user_command(self, cmd):
        """
        Restore saved user-defined command

        Args:
            - cmd: user-defined command (String)

        Returns:
            - True if success to restore (Bool)
        """
        if cmd == "all":
            commands = "\n".join(self.SAVED_COMMANDS.values())
            self.SAVED_COMMANDS = {}
        else:
            if cmd not in self.SAVED_COMMANDS:
                return False
            else:
                commands = self.SAVED_COMMANDS[cmd]
                self.SAVED_COMMANDS.pop(cmd)
        tmp = tmpfile()
        tmp.write(commands)
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()

        return result

    def run_gdbscript_code(self, code):
        """
        Run basic gdbscript code as it is typed in interactively

        Args:
            - code: gdbscript code, lines are splitted by "\n" or ";" (String)

        Returns:
            - True if success to run (Bool)
        """
        tmp = tmpfile()
        tmp.write(code.replace(";", "\n"))
        tmp.flush()
        result = self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    #########################
    #   Debugging Helpers   #
    #########################
    @memoized
    def is_target_remote(self):
        """
        Check if current target is remote

        Returns:
            - True if target is remote (Bool)
        """
        out = self.execute_redirect("info program")
        if out and "serial line" in out: # remote target
            return True

        return False

    @memoized
    def getfile(self):
        """
        Get exec file of debugged program

        Returns:
            - full path to executable file (String)
        """
        result = None
        out = self.execute_redirect('info files')
        if out and '"' in out:
            p = re.compile(".*exec file:\s*`(.*)'")
            m = p.search(out)
            if m:
                result = m.group(1)
            else: # stripped file, get symbol file
                p = re.compile("Symbols from \"([^\"]*)")
                m = p.search(out)
                if m:
                    result = m.group(1)

        return result

    def get_status(self):
        """
        Get execution status of debugged program

        Returns:
            - current status of program (String)
                STOPPED - not being run
                BREAKPOINT - breakpoint hit
                SIGXXX - stopped by signal XXX
                UNKNOWN - unknown, not implemented
        """
        status = "UNKNOWN"
        out = self.execute_redirect("info program")
        for line in out.splitlines():
            if line.startswith("It stopped"):
                if "signal" in line: # stopped by signal
                    status = line.split("signal")[1].split(",")[0].strip()
                    break
                if "breakpoint" in line: # breakpoint hit
                    status = "BREAKPOINT"
                    break
            if "not being run" in line:
                status = "STOPPED"
                break
        return status

    @memoized
    def getpid(self):
        """
        Get PID of the debugged process

        Returns:
            - pid (Int)
        """

        out = None
        status = self.get_status()
        if not status or status == "STOPPED":
            return None

        if self.is_target_remote(): # remote target
            ctx = Option.get("context")
            Option.set("context", None)
            try:
                out = self.execute_redirect("call getpid()")
            except:
                pass

            Option.set("context", ctx)

            if out is None:
                return None
            else:
                out = self.execute_redirect("print $")
                if out:
                    return to_int(out.split("=")[1])
                else:
                    return None

        pid = gdb.selected_inferior().pid
        return int(pid) if pid else None

    def getos(self):
        """
        Get running OS info

        Returns:
            - os version (String)
        """
        # TODO: get remote os by calling uname()
        return os.uname()[0]

    @memoized
    def getarch(self):
        """
        Get architecture of debugged program

        Returns:
            - tuple of architecture info (arch (String), bits (Int))
        """
        arch = "unknown"
        bits = 32
        out = self.execute_redirect('maintenance info sections ?').splitlines()
        for line in out:
            if "file type" in line:
                arch = line.split()[-1][:-1]
                break
        if "64" in arch:
            bits = 64
        return (arch, bits)

    def intsize(self):
        """
        Get dword size of debugged program

        Returns:
            - size (Int)
                + intsize = 4/8 for 32/64-bits arch
        """

        (arch, bits) = self.getarch()
        return bits // 8

    def getregs(self, reglist=None):
        """
        Get value of some or all registers

        Returns:
            - dictionary of {regname(String) : value(Int)}
        """
        if reglist:
            reglist = reglist.replace(",", " ")
        else:
            reglist = ""
        regs = self.execute_redirect("info registers %s" % reglist)
        if not regs:
            return None

        result = {}
        if regs:
            for r in regs.splitlines():
                r = r.split()
                if len(r) > 1 and to_int(r[1]) is not None:
                    result[r[0]] = to_int(r[1])

        return result

    def getreg(self, register):
        """
        Get value of a specific register

        Args:
            - register: register name (String)

        Returns:
            - register value (Int)
        """
        r = register.lower()
        regs = self.execute_redirect("info registers %s" % r)
        if regs:
            regs = regs.splitlines()
            if len(regs) > 1:
                return None
            else:
                result = to_int(regs[0].split()[1])
                return result

        return None

    def set_breakpoint(self, location, temp=0, hard=0):
        """
        Wrapper for GDB break command
            - location: target function or address (String ot Int)

        Returns:
            - True if can set breakpoint
        """
        cmd = "break"
        if hard:
            cmd = "h" + cmd
        if temp:
            cmd = "t" + cmd

        if to_int(location) is not None:
            return peda.execute("%s *0x%x" % (cmd, to_int(location)))
        else:
            return peda.execute("%s %s" % (cmd, location))

    def get_breakpoint(self, num):
        """
        Get info of a specific breakpoint
        TODO: support catchpoint, watchpoint

        Args:
            - num: breakpoint number

        Returns:
            - tuple (Num(Int), Type(String), Disp(Bool), Enb(Bool), Address(Int), What(String), commands(String))
        """
        out = self.execute_redirect("info breakpoints %d" % num)
        if not out or "No breakpoint" in out:
            return None

        lines = out.splitlines()[1:]
        # breakpoint regex
        p = re.compile("^(\d*)\s*(.*breakpoint)\s*(keep|del)\s*(y|n)\s*(0x[^ ]*)\s*(.*)")
        m = p.match(lines[0])
        if not m:
            # catchpoint/watchpoint regex
            p = re.compile("^(\d*)\s*(.*point)\s*(keep|del)\s*(y|n)\s*(.*)")
            m = p.match(lines[0])
            if not m:
                return None
            else:
                (num, type, disp, enb, what) = m.groups()
                addr = ''
        else:
            (num, type, disp, enb, addr, what) = m.groups()

        disp = True if disp == "keep" else False
        enb = True if enb == "y" else False
        addr = to_int(addr)
        m = re.match("in.*at(.*:\d*)", what)
        if m:
            what = m.group(1)
        else:
            if addr: # breakpoint
                what = ""

        commands = ""
        if len(lines) > 1:
            for line in lines[1:]:
                if "already hit" in line: continue
                commands += line + "\n"

        return (num, type, disp, enb, addr, what, commands.rstrip())

    def get_breakpoints(self):
        """
        Get list of current breakpoints

        Returns:
            - list of tuple (Num(Int), Type(String), Disp(Bool), Nnb(Bool), Address(Int), commands(String))
        """
        result = []
        out = self.execute_redirect("info breakpoints")
        if not out:
            return []

        bplist = []
        for line in out.splitlines():
            m = re.match("^(\d*).*", line)
            if m and to_int(m.group(1)):
                bplist += [to_int(m.group(1))]

        for num in bplist:
            r = self.get_breakpoint(num)
            if r:
                result += [r]
        return result

    def save_breakpoints(self, filename):
        """
        Save current breakpoints to file as a script

        Args:
            - filename: target file (String)

        Returns:
            - True if success to save (Bool)
        """
        # use built-in command for gdb 7.2+
        result = self.execute_redirect("save breakpoints %s" % filename)
        if result == '':
            return True

        bplist = self.get_breakpoints()
        if not bplist:
            return False

        try:
            fd = open(filename, "w")
            for (num, type, disp, enb, addr, what, commands) in bplist:
                m = re.match("(.*)point", type)
                if m:
                    cmd = m.group(1).split()[-1]
                else:
                    cmd = "break"
                if "hw" in type and cmd == "break":
                    cmd = "h" + cmd
                if "read" in type:
                    cmd = "r" + cmd
                if "acc" in type:
                    cmd = "a" + cmd

                if not disp:
                    cmd = "t" + cmd
                if what:
                    location = what
                else:
                    location = "*0x%x" % addr
                text = "%s %s" % (cmd, location)
                if commands:
                    if "stop only" not in commands:
                        text += "\ncommands\n%s\nend" % commands
                    else:
                        text += commands.split("stop only", 1)[1]
                fd.write(text + "\n")
            fd.close()
            return True
        except:
            return False

    def get_config_filename(self, name):
        filename = peda.getfile()
        if not filename:
            filename = peda.getpid()
            if not filename:
                filename = 'unknown'

        filename = os.path.basename("%s" % filename)
        tmpl_name = Option.get(name)
        if tmpl_name:
            return tmpl_name.replace("#FILENAME#", filename)
        else:
            return "peda-%s-%s" % (name, filename)

    def save_session(self, filename=None):
        """
        Save current working gdb session to file as a script

        Args:
            - filename: target file (String)

        Returns:
            - True if success to save (Bool)
        """
        session = ""
        if not filename:
            filename = self.get_config_filename("session")

        # exec-wrapper
        out = self.execute_redirect("show exec-wrapper")
        wrapper = out.split('"')[1]
        if wrapper:
            session += "set exec-wrapper %s\n" % wrapper

        try:
            # save breakpoints
            self.save_breakpoints(filename)
            fd = open(filename, "a+")
            fd.write("\n" + session)
            fd.close()
            return True
        except:
            return False

    def restore_session(self, filename=None):
        """
        Restore previous saved working gdb session from file

        Args:
            - filename: source file (String)

        Returns:
            - True if success to restore (Bool)
        """
        if not filename:
            filename = self.get_config_filename("session")

        # temporarily save and clear breakpoints
        tmp = tmpfile()
        self.save_breakpoints(tmp.name)
        self.execute("delete")
        result = self.execute("source %s" % filename)
        if not result:
            self.execute("source %s" % tmp.name)
        tmp.close()
        return result

    @memoized
    def assemble(self, asmcode, bits=None):
        """
        Assemble ASM instructions using NASM
            - asmcode: input ASM instructions, multiple instructions are separated by ";" (String)

        Returns:
            - bin code (raw bytes)
        """
        if bits is None:
            (arch, bits) = self.getarch()
        return Nasm.assemble(asmcode, bits)

    def disassemble(self, *arg):
        """
        Wrapper for disassemble command
            - arg: args for disassemble command

        Returns:
            - text code (String)
        """
        code = ""
        modif = ""
        arg = list(arg)
        if len(arg) > 1:
            if "/" in arg[0]:
                modif = arg[0]
                arg = arg[1:]
        if len(arg) == 1 and to_int(arg[0]) != None:
            arg += [to_hex(to_int(arg[0]) + 32)]

        self.execute("set disassembly-flavor intel")
        out = self.execute_redirect("disassemble %s %s" % (modif, ",".join(arg)))
        if not out:
            return None
        else:
            code = out

        return code

    @memoized
    def prev_inst(self, address, count=1):
        """
        Get previous instructions at an address

        Args:
            - address: address to get previous instruction (Int)
            - count: number of instructions to read (Int)

        Returns:
            - list of tuple (address(Int), code(String))
        """
        result = []
        backward = 64+16*count
        for i in range(backward):
            if self.getpid() and not self.is_address(address-backward+i):
                continue

            code = self.execute_redirect("disassemble %s, %s" % (to_hex(address-backward+i), to_hex(address+1)))
            if code and ("%x" % address) in code:
                lines = code.strip().splitlines()[1:-1]
                if len(lines) > count and "(bad)" not in " ".join(lines):
                    for line in lines[-count-1:-1]:
                        (addr, code) = line.split(":", 1)
                        addr = re.search("(0x[^ ]*)", addr).group(1)
                        result += [(to_int(addr), code)]
                    return result
        return None

    @memoized
    def current_inst(self, address):
        """
        Parse instruction at an address

        Args:
            - address: address to get next instruction (Int)

        Returns:
            - tuple of (address(Int), code(String))
        """
        out = self.execute_redirect("x/i 0x%x" % address)
        if not out:
            return None

        (addr, code) = out.split(":", 1)
        addr = re.search("(0x[^ ]*)", addr).group(1)
        addr = to_int(addr)
        code = code.strip()

        return (addr, code)

    @memoized
    def next_inst(self, address, count=1):
        """
        Get next instructions at an address

        Args:
            - address: address to get next instruction (Int)
            - count: number of instructions to read (Int)

        Returns:
            - - list of tuple (address(Int), code(String))
        """
        result = []
        code = self.execute_redirect("x/%di 0x%x" % (count+1, address))
        if not code:
            return None

        lines = code.strip().splitlines()
        for i in range(1, count+1):
            (addr, code) = lines[i].split(":", 1)
            addr = re.search("(0x[^ ]*)", addr).group(1)
            result += [(to_int(addr), code)]
        return result

    @memoized
    def disassemble_around(self, address, count=8):
        """
        Disassemble instructions nearby current PC or an address

        Args:
            - address: start address to disassemble around (Int)
            - count: number of instructions to disassemble

        Returns:
            - text code (String)
        """
        count = min(count, 256)
        pc = address
        if pc is None:
            return None

        # check if address is reachable
        if not self.execute_redirect("x/x 0x%x" % pc):
            return None

        prev_code = self.prev_inst(pc, count//2-1)
        if prev_code:
            start = prev_code[0][0]
        else:
            start = pc
        if start == pc:
            count = count//2

        code = self.execute_redirect("x/%di 0x%x" % (count, start))
        if "0x%x" % pc not in code:
            code = self.execute_redirect("x/%di 0x%x" % (count//2, pc))

        return code.rstrip()

    @memoized
    def xrefs(self, search="", filename=None):
        """
        Search for all call references or data access to a function/variable

        Args:
            - search: function or variable to search for (String)
            - filename: binary/library to search (String)

        Returns:
            - list of tuple (address(Int), asm instruction(String))
        """
        result = []
        if not filename:
            filename = self.getfile()

        if not filename:
            return None
        vmap = self.get_vmmap(filename)
        elfbase = vmap[0][0] if vmap else 0

        if to_int(search) is not None:
            search = "%x" % to_int(search)

        search_data = 1
        if search == "":
            search_data = 0

        out = execute_external_command("%s -M intel -z --prefix-address -d '%s' | grep '%s'" % (config.OBJDUMP, filename, search))

        for line in out.splitlines():
            if not line: continue
            addr = to_int("0x" + line.split()[0].strip())
            if not addr: continue

            # update with runtime values
            if addr < elfbase:
                addr += elfbase
            out = self.execute_redirect("x/i 0x%x" % addr)
            if out:
                line = out
                p = re.compile("\s*(0x[^ ]*).*?:\s*([^ ]*)\s*(.*)")
            else:
                p = re.compile("(.*?)\s*<.*?>\s*([^ ]*)\s*(.*)")

            m = p.search(line)
            if m:
                (address, opcode, opers) = m.groups()
                if "call" in opcode and search in opers:
                    result += [(addr, line.strip())]
                if search_data:
                     if "mov" in opcode and search in opers:
                         result += [(addr, line.strip())]

        return result

    def _get_function_args_32(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - i386
        """
        if not argc:
            argc = 0
            p = re.compile(".*mov.*\[esp(.*)\],")
            matches = p.findall(code)
            if matches:
                l = len(matches)
                for v in matches:
                    if v.startswith("+"):
                        offset = to_int(v[1:])
                        if offset is not None and (offset//4) > l:
                            continue
                    argc += 1
            else: # try with push style
                argc = code.count("push")

        argc = min(argc, 6)
        if argc == 0:
            return []

        args = []
        sp = self.getreg("sp")
        mem = self.dumpmem(sp, sp+4*argc)
        for i in range(argc):
            args += [struct.unpack("<L", mem[i*4:(i+1)*4])[0]]

        return args

    def _get_function_args_64(self, code, argc=None):
        """
        Guess the number of arguments passed to a function - x86_64
        """

        # just retrieve max 6 args
        arg_order = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        p = re.compile(":\s*([^ ]*)\s*(.*),")
        matches = p.findall(code)
        regs = [r for (_, r) in matches]
        p = re.compile(("di|si|dx|cx|r8|r9"))
        m = p.findall(" ".join(regs))
        m = list(set(m)) # uniqify
        argc = 0
        if "si" in m and "di" not in m: # dirty fix
            argc += 1
        argc += m.count("di")
        if argc > 0:
            argc += m.count("si")
        if argc > 1:
            argc += m.count("dx")
        if argc > 2:
            argc += m.count("cx")
        if argc > 3:
            argc += m.count("r8")
        if argc > 4:
            argc += m.count("r9")

        if argc == 0:
            return []

        args = []
        regs = self.getregs()
        for i in range(argc):
            args += [regs[arg_order[i]]]

        return args

    def get_function_args(self, argc=None):
        """
        Get the guessed arguments passed to a function when stopped at a call instruction

        Args:
            - argc: force to get specific number of arguments (Int)

        Returns:
            - list of arguments (List)
        """

        args = []
        regs = self.getregs()
        if regs is None:
            return []

        (arch, bits) = self.getarch()
        pc = self.getreg("pc")
        prev_insts = self.prev_inst(pc, 12)

        code = ""
        if not prev_insts:
            return []

        for (addr, inst) in prev_insts[::-1]:
            if "call" in inst.strip().split()[0]:
                break
            code = "0x%x:%s\n" % (addr, inst) + code

        if "i386" in arch:
            args = self._get_function_args_32(code, argc)
        if "64" in arch:
            args = self._get_function_args_64(code, argc)

        return args

    @memoized
    def backtrace_depth(self, sp=None):
        """
        Get number of frames in backtrace

        Args:
            - sp: stack pointer address, for caching (Int)

        Returns:
            - depth: number of frames (Int)
        """
        backtrace = self.execute_redirect("backtrace")
        return backtrace.count("#")

    def stepuntil(self, inst, mapname=None, depth=None):
        """
        Step execution until next "inst" instruction within a specific memory range

        Args:
            - inst: the instruction to reach (String)
            - mapname: name of virtual memory region to check for the instruction (String)
            - depth: backtrace depth (Int)

        Returns:
            - tuple of (depth, instruction)
                + depth: current backtrace depth (Int)
                + instruction: current instruction (String)
        """

        if not self.getpid():
            return None

        maxdepth = to_int(Option.get("tracedepth"))
        if not maxdepth:
            maxdepth = 0xffffffff

        maps = self.get_vmmap()
        binname = self.getfile()
        if mapname is None:
            mapname = binname
        mapname = mapname.replace(" ", "").split(",") + [binname]
        targetmap = []
        for m in mapname:
            targetmap += self.get_vmmap(m)
        binmap = self.get_vmmap("binary")

        current_instruction = ""
        pc = self.getreg("pc")

        if depth is None:
            current_depth = self.backtrace_depth(self.getreg("sp"))
        else:
            current_depth = depth
        old_status = self.get_status()

        while True:
            status = self.get_status()
            if status != old_status:
                if "SIG" in status and status[3:] not in ["TRAP"] and not to_int(status[3:]): # ignore TRAP and numbered signals
                    current_instruction = "Interrupted: %s" % status
                    call_depth = current_depth
                    break
                if "STOP" in status:
                    current_instruction = "End of execution"
                    call_depth = current_depth
                    break

            call_depth = self.backtrace_depth(self.getreg("sp"))
            current_instruction = self.execute_redirect("x/i $pc")
            if not current_instruction:
                current_instruction = "End of execution"
                break

            p = re.compile(".*?(0x[^ :]*)")
            addr = p.search(current_instruction).group(1)
            addr = to_int(addr)
            if addr is None:
                break

            #p = re.compile(".*?:\s*([^ ]*)")
            p = re.compile(".*?:\s*(.*)")
            code = p.match(current_instruction).group(1)
            found = 0
            for i in inst.replace(",", " ").split():
                if re.match(i.strip(), code.strip()):
                    if self.is_address(addr, targetmap) and addr != pc:
                        found = 1
                        break
            if found != 0:
                break
            self.execute_redirect("stepi", silent=True)
            if not self.is_address(addr, targetmap) or call_depth > maxdepth:
                self.execute_redirect("finish", silent=True)
            pc = 0

        return (call_depth - current_depth, current_instruction.strip())

    def get_eflags(self):
        """
        Get flags value from EFLAGS register

        Returns:
            - dictionary of named flags
        """

        # Eflags bit masks, source vdb
        EFLAGS_CF = 1 << 0
        EFLAGS_PF = 1 << 2
        EFLAGS_AF = 1 << 4
        EFLAGS_ZF = 1 << 6
        EFLAGS_SF = 1 << 7
        EFLAGS_TF = 1 << 8
        EFLAGS_IF = 1 << 9
        EFLAGS_DF = 1 << 10
        EFLAGS_OF = 1 << 11

        flags = {"CF":0, "PF":0, "AF":0, "ZF":0, "SF":0, "TF":0, "IF":0, "DF":0, "OF":0}
        eflags = self.getreg("eflags")
        if not eflags:
            return None
        flags["CF"] = bool(eflags & EFLAGS_CF)
        flags["PF"] = bool(eflags & EFLAGS_PF)
        flags["AF"] = bool(eflags & EFLAGS_AF)
        flags["ZF"] = bool(eflags & EFLAGS_ZF)
        flags["SF"] = bool(eflags & EFLAGS_SF)
        flags["TF"] = bool(eflags & EFLAGS_TF)
        flags["IF"] = bool(eflags & EFLAGS_IF)
        flags["DF"] = bool(eflags & EFLAGS_DF)
        flags["OF"] = bool(eflags & EFLAGS_OF)

        return flags

    def set_eflags(self, flagname, value=True):
        """
        Set/clear value of a flag register

        Returns:
            - True if success (Bool)
        """

        # Eflags bit masks, source vdb
        EFLAGS_CF = 1 << 0
        EFLAGS_PF = 1 << 2
        EFLAGS_AF = 1 << 4
        EFLAGS_ZF = 1 << 6
        EFLAGS_SF = 1 << 7
        EFLAGS_TF = 1 << 8
        EFLAGS_IF = 1 << 9
        EFLAGS_DF = 1 << 10
        EFLAGS_OF = 1 << 11

        flags = {"carry": "CF", "parity": "PF", "adjust": "AF", "zero": "ZF", "sign": "SF",
                    "trap": "TF", "interrupt": "IF", "direction": "DF", "overflow": "OF"}

        if flagname not in flags:
            return False

        eflags = self.get_eflags()
        if not eflags:
            return False

        if eflags[flags[flagname]] != value: # switch value
            reg_eflags = self.getreg("eflags")
            reg_eflags ^= eval("EFLAGS_%s" % flags[flagname])
            result = self.execute("set $eflags = 0x%x" % reg_eflags)
            return result

        return True

    def eval_target(self, inst):
        """
        Evaluate target address of an instruction, used for jumpto decision

        Args:
            - inst: AMS instruction text (String)

        Returns:
            - target address (Int)
        """

        target = None
        inst = inst.strip()
        opcode = inst.split(":\t")[-1].split()[0]
        # this regex includes x86_64 RIP relateive address reference
        p = re.compile(".*?:\s*[^ ]*\s*(.* PTR ).*(0x[^ ]*)")
        m = p.search(inst)
        if not m:
            p = re.compile(".*?:\s.*(0x[^ ]*)")
            m = p.search(inst)
            if m:
                target = m.group(1)
            else:
                target = None
        else:
            if "]" in m.group(2): # e.g DWORD PTR [ebx+0xc]
                p = re.compile(".*?:\s*[^ ]*\s*(.* PTR ).*\[(.*)\]")
                m = p.search(inst)
            target = self.parse_and_eval("%s[%s]" % (m.group(1), m.group(2).strip()))

        return to_int(target)

    def testjump(self, inst=None):
        """
        Test if jump instruction is taken or not

        Returns:
            - (status, address of target jumped instruction)
        """

        flags = self.get_eflags()
        if not flags:
            return None

        if not inst:
            pc = self.getreg("pc")
            inst = self.execute_redirect("x/i 0x%x" % pc)
            if not inst:
                return None

        opcode = inst.split(":\t")[-1].split()[0]
        next_addr = self.eval_target(inst)
        if next_addr is None:
            next_addr = 0

        if opcode == "jmp":
            return next_addr
        if opcode == "je" and flags["ZF"]:
            return next_addr
        if opcode == "jne" and not flags["ZF"]:
            return next_addr
        if opcode == "jg" and not flags["ZF"] and (flags["SF"] == flags["OF"]):
            return next_addr
        if opcode == "jge" and (flags["SF"] == flags["OF"]):
            return next_addr
        if opcode == "ja" and not flags["CF"] and not flags["ZF"]:
            return next_addr
        if opcode == "jae" and not flags["CF"]:
            return next_addr
        if opcode == "jl" and (flags["SF"] != flags["OF"]):
            return next_addr
        if opcode == "jle" and (flags["ZF"] or (flags["SF"] != flags["OF"])):
            return next_addr
        if opcode == "jb" and flags["CF"]:
            return next_addr
        if opcode == "jbe" and (flags["CF"] or flags["ZF"]):
            return next_addr
        if opcode == "jo" and flags["OF"]:
            return next_addr
        if opcode == "jno" and not flags["OF"]:
            return next_addr
        if opcode == "jz" and flags["ZF"]:
            return next_addr
        if opcode == "jnz" and flags["OF"]:
            return next_addr

        return None

    def take_snapshot(self):
        """
        Take a snapshot of current process
        Warning: this is not thread safe, do not use with multithread program

        Returns:
            - dictionary of snapshot data
        """
        if not self.getpid():
            return None

        maps =  self.get_vmmap()
        if not maps:
            return None

        snapshot = {}
        # get registers
        snapshot["reg"] = self.getregs()
        # get writable memory regions
        snapshot["mem"] = {}
        for (start, end, perm, _) in maps:
            if "w" in perm:
                snapshot["mem"][start] = self.dumpmem(start, end)

        return snapshot

    def save_snapshot(self, filename=None):
        """
        Save a snapshot of current process to file
        Warning: this is not thread safe, do not use with multithread program

        Args:
            - filename: target file to save snapshot

        Returns:
            - Bool
        """
        if not filename:
            filename = self.get_config_filename("snapshot")

        snapshot = self.take_snapshot()
        if not snapshot:
            return False
        # dump to file
        fd = open(filename, "wb")
        pickle.dump(snapshot, fd, pickle.HIGHEST_PROTOCOL)
        fd.close()

        return True

    def give_snapshot(self, snapshot):
        """
        Restore a saved snapshot of current process
        Warning: this is not thread safe, do not use with multithread program

        Returns:
            - Bool
        """
        if not snapshot or not self.getpid():
            return False

        # restore memory regions
        for (addr, buf) in snapshot["mem"].items():
            self.writemem(addr, buf)

        # restore registers, SP will be the last one
        for (r, v) in snapshot["reg"].items():
            self.execute("set $%s = 0x%x" % (r, v))
            if r.endswith("sp"):
                sp = v
        self.execute("set $sp = 0x%x" % sp)

        return True

    def restore_snapshot(self, filename=None):
        """
        Restore a saved snapshot of current process from file
        Warning: this is not thread safe, do not use with multithread program

        Args:
            - file: saved snapshot

        Returns:
            - Bool
        """
        if not filename:
            filename = self.get_config_filename("snapshot")

        fd = open(filename, "rb")
        snapshot = pickle.load(fd)
        return self.give_snapshot(snapshot)


    #########################
    #   Memory Operations   #
    #########################
    @memoized
    def get_vmmap(self, name=None):
        """
        Get virtual memory mapping address ranges of debugged process

        Args:
            - name: name/address of binary/library to get mapping range (String)
                + name = "binary" means debugged program
                + name = "all" means all virtual maps

        Returns:
            - list of virtual mapping ranges (start(Int), end(Int), permission(String), mapname(String))

        """
        def _get_offline_maps():
            name = self.getfile()
            if not name:
                return None
            headers = self.elfheader()
            binmap = []
            hlist = [x for x in headers.items() if x[1][2] == 'code']
            hlist = sorted(hlist, key=lambda x:x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "rx-p", name)]

            hlist = [x for x in headers.items() if x[1][2] == 'rodata']
            hlist = sorted(hlist, key=lambda x:x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "r--p", name)]

            hlist = [x for x in headers.items() if x[1][2] == 'data']
            hlist = sorted(hlist, key=lambda x:x[1][0])
            binmap += [(hlist[0][1][0], hlist[-1][1][1], "rw-p", name)]

            return binmap

        def _get_allmaps_osx(pid, remote=False):
            maps = []
            #_DATA                 00007fff77975000-00007fff77976000 [    4K] rw-/rw- SM=COW  /usr/lib/system/libremovefile.dylib
            pattern = re.compile("([^\n]*)\s*  ([0-9a-f][^-\s]*)-([^\s]*) \[.*\]\s([^/]*).*  (.*)")

            if remote: # remote target, not yet supported
                return maps
            else: # local target
                try:  out = execute_external_command("/usr/bin/vmmap -w %s" % self.getpid())
                except: error_msg("could not read vmmap of process")

            matches = pattern.findall(out)
            if matches:
                for (name, start, end, perm, mapname) in matches:
                    if name.startswith("Stack"):
                        mapname = "[stack]"
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "":
                        mapname = name.strip()
                    maps += [(start, end, perm, mapname)]
            return maps


        def _get_allmaps_freebsd(pid, remote=False):
            maps = []
            mpath = "/proc/%s/map" % pid
            # 0x8048000 0x8049000 1 0 0xc36afdd0 r-x 1 0 0x1000 COW NC vnode /path/to/file NCH -1
            pattern = re.compile("0x([0-9a-f]*) 0x([0-9a-f]*)(?: [^ ]*){3} ([rwx-]*)(?: [^ ]*){6} ([^ ]*)")

            if remote: # remote target, not yet supported
                return maps
            else: # local target
                try:  out = open(mpath).read()
                except: error_msg("could not open %s; is procfs mounted?" % mpath)

            matches = pattern.findall(out)
            if matches:
                for (start, end, perm, mapname) in matches:
                    if start[:2] in ["bf", "7f", "ff"] and "rw" in perm:
                        mapname = "[stack]"
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "-":
                        if start == maps[-1][1] and maps[-1][-1][0] == "/":
                            mapname = maps[-1][-1]
                        else:
                            mapname = "mapped"
                    maps += [(start, end, perm, mapname)]
            return maps

        def _get_allmaps_linux(pid, remote=False):
            maps = []
            mpath = "/proc/%s/maps" % pid
            #00400000-0040b000 r-xp 00000000 08:02 538840  /path/to/file
            pattern = re.compile("([0-9a-f]*)-([0-9a-f]*) ([rwxps-]*)(?: [^ ]*){3} *(.*)")

            if remote: # remote target
                tmp = tmpfile()
                self.execute("remote get %s %s" % (mpath, tmp.name))
                tmp.seek(0)
                out = tmp.read()
                tmp.close()
            else: # local target
                out = open(mpath).read()

            matches = pattern.findall(out)
            if matches:
                for (start, end, perm, mapname) in matches:
                    start = to_int("0x%s" % start)
                    end = to_int("0x%s" % end)
                    if mapname == "":
                        mapname = "mapped"
                    maps += [(start, end, perm, mapname)]
            return maps

        result = []
        pid = self.getpid()
        if not pid: # not running, try to use elfheader()
            try:
                return _get_offline_maps()
            except:
                return []

        # retrieve all maps
        os   = self.getos()
        rmt  = self.is_target_remote()
        maps = []
        try:
            if   os == "FreeBSD": maps = _get_allmaps_freebsd(pid, rmt)
            elif os == "Linux"  : maps = _get_allmaps_linux(pid, rmt)
            elif os == "Darwin" : maps = _get_allmaps_osx(pid, rmt)
        except Exception as e:
            if Option.get("debug") == "on":
                msg("Exception: %s" %e)
                traceback.print_exc()

        # select maps matched specific name
        if name == "binary":
            name = self.getfile()
        if name is None or name == "all":
            name = ""

        if to_int(name) is None:
            for (start, end, perm, mapname) in maps:
                if name in mapname:
                    result += [(start, end, perm, mapname)]
        else:
            addr = to_int(name)
            for (start, end, perm, mapname) in maps:
                if start <= addr and addr < end:
                    result += [(start, end, perm, mapname)]

        return result

    @memoized
    def get_vmrange(self, address, maps=None):
        """
        Get virtual memory mapping range of an address

        Args:
            - address: target address (Int)
            - maps: only find in provided maps (List)

        Returns:
            - tuple of virtual memory info (start, end, perm, mapname)
        """
        if address is None:
            return None
        if maps is None:
            maps = self.get_vmmap()
        if maps:
            for (start, end, perm, mapname) in maps:
                if start <= address and end > address:
                    return (start, end, perm, mapname)
        # failed to get the vmmap
        else:
            try:
                gdb.selected_inferior().read_memory(address, 1)
                start = address & 0xfffffffffffff000
                end = start + 0x1000
                return (start, end, 'rwx', 'unknown')
            except:
                return None


    @memoized
    def is_executable(self, address, maps=None):
        """
        Check if an address is executable

        Args:
            - address: target address (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if address belongs to an executable address range (Bool)
        """
        vmrange = self.get_vmrange(address, maps)
        if vmrange and "x" in vmrange[2]:
            return True
        else:
            return False

    @memoized
    def is_writable(self, address, maps=None):
        """
        Check if an address is writable

        Args:
            - address: target address (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if address belongs to a writable address range (Bool)
        """
        vmrange = self.get_vmrange(address, maps)
        if vmrange and "w" in vmrange[2]:
            return True
        else:
            return False

    @memoized
    def is_address(self, value, maps=None):
        """
        Check if a value is a valid address (belongs to a memory region)

        Args:
            - value (Int)
            - maps: only check in provided maps (List)

        Returns:
            - True if value belongs to an address range (Bool)
        """
        vmrange = self.get_vmrange(value, maps)
        return vmrange is not None

    @memoized
    def get_disasm(self, address, count=1):
        """
        Get the ASM code of instruction at address

        Args:
            - address: address to read instruction (Int)
            - count: number of code lines (Int)

        Returns:
            - asm code (String)
        """
        code = self.execute_redirect("x/%di 0x%x" % (count, address))
        if code:
            return code.rstrip()
        else:
            return ""

    def dumpmem(self, start, end):
        """
        Dump process memory from start to end

        Args:
            - start: start address (Int)
            - end: end address (Int)

        Returns:
            - memory content (raw bytes)
        """
        mem = None
        logfd = tmpfile(is_binary_file=True)
        logname = logfd.name
        out = self.execute_redirect("dump memory %s 0x%x 0x%x" % (logname, start, end))
        if out is None:
            return None
        else:
            logfd.flush()
            mem = logfd.read()
            logfd.close()

        return mem

    def readmem(self, address, size):
        """
        Read content of memory at an address

        Args:
            - address: start address to read (Int)
            - size: bytes to read (Int)

        Returns:
            - memory content (raw bytes)
        """
        # try fast dumpmem if it works
        mem = self.dumpmem(address, address+size)
        if mem is not None:
            return mem

        # failed to dump, use slow x/gx way
        mem = ""
        out = self.execute_redirect("x/%dbx 0x%x" % (size, address))
        if out:
            for line in out.splitlines():
                bytes = line.split(":\t")[-1].split()
                mem += "".join([chr(int(c, 0)) for c in bytes])

        return mem

    def read_int(self, address, intsize=None):
        """
        Read an interger value from memory

        Args:
            - address: address to read (Int)
            - intsize: force read size (Int)

        Returns:
            - mem value (Int)
        """
        if not intsize:
            intsize = self.intsize()
        value = self.readmem(address, intsize)
        if value:
            value = to_int("0x" + codecs.encode(value[::-1], 'hex'))
            return value
        else:
            return None


    def read_long(self, address):
        """
        Read a long long value from memory

        Args:
            - address: address to read (Int)

        Returns:
            - mem value (Long Long)
        """
        return self.read_int(address, 8)

    def writemem(self, address, buf):
        """
        Write buf to memory start at an address

        Args:
            - address: start address to write (Int)
            - buf: data to write (raw bytes)

        Returns:
            - number of written bytes (Int)
        """
        out = None
        if not buf:
            return 0

        if self.getpid():
            # try fast restore mem
            tmp = tmpfile(is_binary_file=True)
            tmp.write(buf)
            tmp.flush()
            out = self.execute_redirect("restore %s binary 0x%x" % (tmp.name, address))
            tmp.close()
        if not out: # try the slow way
            for i in range(len(buf)):
                if not self.execute("set {char}0x%x = 0x%x" % (address+i, ord(buf[i]))):
                    return i
            return i+1
        elif "error" in out: # failed to write the whole buf, find written byte
            for i in range(0, len(buf), 1):
                if not self.is_address(address+i):
                    return i
        else:
            return len(buf)

    def write_int(self, address, value, intsize=None):
        """
        Write an interger value to memory

        Args:
            - address: address to read (Int)
            - value: int to write to (Int)
            - intsize: force write size (Int)

        Returns:
            - Bool
        """
        if not intsize:
            intsize = self.intsize()
        buf = hex2str(value, intsize).ljust(intsize, "\x00")[:intsize]
        saved = self.readmem(address, intsize)
        if not saved:
            return False

        ret = self.writemem(address, buf)
        if ret != intsize:
            self.writemem(address, saved)
            return False
        return True

    def write_long(self, address, value):
        """
        Write a long long value to memory

        Args:
            - address: address to read (Int)
            - value: value to write to

        Returns:
            - Bool
        """
        return self.write_int(address, value, 8)

    def cmpmem(self, start, end, buf):
        """
        Compare contents of a memory region with a buffer

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - buf: raw bytes

        Returns:
            - dictionary of array of diffed bytes in hex (Dictionary)
            {123: [("A", "B"), ("C", "C"))]}
        """
        line_len = 32
        if end < start:
            (start, end) = (end, start)

        mem = self.dumpmem(start, end)
        if mem is None:
            return None

        length = min(len(mem), len(buf))
        result = {}
        lineno = 0
        for i in range(length//line_len):
            diff = 0
            bytes_ = []
            for j in range(line_len):
                offset = i*line_len+j
                bytes_ += [(mem[offset:offset + 1], buf[offset:offset + 1])]
                if mem[offset] != buf[offset]:
                    diff = 1
            if diff == 1:
                result[start+lineno] = bytes_
            lineno += line_len

        bytes_ = []
        diff = 0
        for i in range(length % line_len):
            offset = lineno+i
            bytes_ += [(mem[offset:offset + 1], buf[offset:offset + 1])]
            if mem[offset] != buf[offset]:
                diff = 1
        if diff == 1:
            result[start+lineno] = bytes_

        return result

    def xormem(self, start, end, key):
        """
        XOR a memory region with a key

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - key: XOR key (String)

        Returns:
            - xored memory content (raw bytes)
        """
        mem = self.dumpmem(start, end)
        if mem is None:
            return None

        if to_int(key) != None:
            key = hex2str(to_int(key), self.intsize())
        mem = list(bytes_iterator(mem))
        for index, char in enumerate(mem):
            key_idx = index % len(key)
            mem[index] = chr(ord(char) ^ ord(key[key_idx]))

        buf = b"".join([to_binary_string(x) for x in mem])
        bytes = self.writemem(start, buf)
        return buf

    def searchmem(self, start, end, search, mem=None):
        """
        Search for all instances of a pattern in memory from start to end

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - search: string or python regex pattern (String)
            - mem: cached mem to not re-read for repeated searches (raw bytes)

        Returns:
            - list of found result: (address(Int), hex encoded value(String))

        """

        result = []
        if end < start:
            (start, end) = (end, start)

        if mem is None:
            mem = self.dumpmem(start, end)

        if not mem:
            return result

        if isinstance(search, six.string_types) and search.startswith("0x"):
            # hex number
            search = search[2:]
            if len(search) %2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
            search = re.escape(search)

        # Convert search to bytes if is not already
        if not isinstance(search, bytes):
            search = search.encode('utf-8')

        try:
            p = re.compile(search)
        except:
            search = re.escape(search)
            p = re.compile(search)

        found = list(p.finditer(mem))
        for m in found:
            index = 1
            if m.start() == m.end() and m.lastindex:
                index = m.lastindex+1
            for i in range(0,index):
                if m.start(i) != m.end(i):
                    result += [(start + m.start(i), codecs.encode(mem[m.start(i):m.end(i)], 'hex'))]

        return result

    def searchmem_by_range(self, mapname, search):
        """
        Search for all instances of a pattern in virtual memory ranges

        Args:
            - search: string or python regex pattern (String)
            - mapname: name of virtual memory range (String)

        Returns:
            - list of found result: (address(Int), hex encoded value(String))
        """

        result = []
        ranges = self.get_vmmap(mapname)
        if ranges:
            for (start, end, perm, name) in ranges:
                if "r" in perm:
                    result += self.searchmem(start, end, search)

        return result

    @memoized
    def search_reference(self, search, mapname=None):
        """
        Search for all references to a value in memory ranges

        Args:
            - search: string or python regex pattern (String)
            - mapname: name of target virtual memory range (String)

        Returns:
            - list of found result: (address(int), hex encoded value(String))
        """

        maps = self.get_vmmap()
        ranges = self.get_vmmap(mapname)
        result = []
        search_result = []
        for (start, end, perm, name) in maps:
            if "r" in perm:
                search_result += self.searchmem(start, end, search)

        for (start, end, perm, name) in ranges:
            for (a, v) in search_result:
                result += self.searchmem(start, end, to_address(a))

        return result

    @memoized
    def search_address(self, searchfor="stack", belongto="binary"):
        """
        Search for all valid addresses in memory ranges

        Args:
            - searchfor: memory region to search for addresses (String)
            - belongto: memory region that target addresses belong to (String)

        Returns:
            - list of found result: (address(Int), value(Int))
        """

        result = []
        maps = self.get_vmmap()
        if maps is None:
            return result

        searchfor_ranges = self.get_vmmap(searchfor)
        belongto_ranges = self.get_vmmap(belongto)
        step = self.intsize()
        for (start, end, _, _) in searchfor_ranges[::-1]: # dirty trick, to search in rw-p mem first
            mem = self.dumpmem(start, end)
            if not mem:
                continue
            for i in range(0, len(mem), step):
                search = "0x" + codecs.encode(mem[i:i+step][::-1], 'hex').decode('utf-8')
                addr = to_int(search)
                if self.is_address(addr, belongto_ranges):
                    result += [(start+i, addr)]

        return result

    @memoized
    def search_pointer(self, searchfor="stack", belongto="binary"):
        """
        Search for all valid pointers in memory ranges

        Args:
            - searchfor: memory region to search for pointers (String)
            - belongto: memory region that pointed addresses belong to (String)

        Returns:
            - list of found result: (address(Int), value(Int))
        """

        search_result = []
        result = []
        maps = self.get_vmmap()
        searchfor_ranges = self.get_vmmap(searchfor)
        belongto_ranges = self.get_vmmap(belongto)
        step = self.intsize()
        for (start, end, _, _) in searchfor_ranges[::-1]:
            mem = self.dumpmem(start, end)
            if not mem:
                continue
            for i in range(0, len(mem), step):
                search = "0x" + codecs.encode(mem[i:i+step][::-1], 'hex').decode('utf-8')
                addr = to_int(search)
                if self.is_address(addr):
                    (v, t, vn) = self.examine_mem_value(addr)
                    if t != 'value':
                        if self.is_address(to_int(vn), belongto_ranges):
                            if (to_int(v), v) not in search_result:
                                search_result += [(to_int(v), v)]

            for (a, v) in search_result:
                result += self.searchmem(start, end, to_address(a), mem)

        return result

    @memoized
    def examine_mem_value(self, value):
        """
        Examine a value in memory for its type and reference

        Args:
            - value: value to examine (Int)

        Returns:
            - tuple of (value(Int), type(String), next_value(Int))
        """
        def examine_data(value, bits=32):
            out = self.execute_redirect("x/%sx 0x%x" % ("g" if bits == 64 else "w", value))
            if out:
                v = out.split(":\t")[-1].strip()
                if is_printable(int2hexstr(to_int(v), bits//8)):
                    out = self.execute_redirect("x/s 0x%x" % value)
            return out

        result = (None, None, None)
        if value is None:
            return result

        maps = self.get_vmmap()
        binmap = self.get_vmmap("binary")

        (arch, bits) = self.getarch()
        if not self.is_address(value): # a value
            result = (to_hex(value), "value", "")
            return result
        else:
            (_, _, _, mapname) = self.get_vmrange(value)

        # check for writable first so rwxp mem will be treated as data
        if self.is_writable(value): # writable data address
            out = examine_data(value, bits)
            if out:
                result = (to_hex(value), "data", out.split(":", 1)[1].strip())

        elif self.is_executable(value): # code/rodata address
            if self.is_address(value, binmap):
                headers = self.elfheader()
            else:
                headers = self.elfheader_solib(mapname)

            if headers:
                headers = sorted(headers.items(), key=lambda x: x[1][1])
                for (k, (start, end, type)) in headers:
                    if value >= start and value < end:
                        if type == "code":
                            out = self.get_disasm(value)
                            p = re.compile(".*?0x[^ ]*?\s(.*)")
                            m = p.search(out)
                            result = (to_hex(value), "code", m.group(1))
                        else: # rodata address
                            out = examine_data(value, bits)
                            result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
                        break

                if result[0] is None: # not fall to any header section
                    out = examine_data(value, bits)
                    result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())

            else: # not belong to any lib: [heap], [vdso], [vsyscall], etc
                out = self.get_disasm(value)
                if "(bad)" in out:
                    out = examine_data(value, bits)
                    result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
                else:
                    p = re.compile(".*?0x[^ ]*?\s(.*)")
                    m = p.search(out)
                    result = (to_hex(value), "code", m.group(1))

        else: # readonly data address
            out = examine_data(value, bits)
            if out:
                result = (to_hex(value), "rodata", out.split(":", 1)[1].strip())
            else:
                result = (to_hex(value), "rodata", "MemError")

        return result

    @memoized
    def examine_mem_reference(self, value, depth=5):
        """
        Deeply examine a value in memory for its references

        Args:
            - value: value to examine (Int)

        Returns:
            - list of tuple of (value(Int), type(String), next_value(Int))
        """
        result = []
        if depth <= 0:
            depth = 0xffffffff

        (v, t, vn) = self.examine_mem_value(value)
        while vn is not None:
            if len(result) > depth:
                _v, _t, _vn = result[-1]
                result[-1] = (_v, _t, "--> ...")
                break

            result += [(v, t, vn)]
            if v == vn or to_int(v) == to_int(vn): # point to self
                break
            if to_int(vn) is None:
                break
            if to_int(vn) in [to_int(v) for (v, _, _) in result]: # point back to previous value
                break
            (v, t, vn) = self.examine_mem_value(to_int(vn))

        return result

    @memoized
    def format_search_result(self, result, display=256):
        """
        Format the result from various memory search commands

        Args:
            - result: result of search commands (List)
            - display: number of items to display

        Returns:
            - text: formatted text (String)
        """

        text = ""
        if not result:
            text = "Not found"
        else:
            maxlen = 0
            maps = self.get_vmmap()
            shortmaps = []
            for (start, end, perm, name) in maps:
                shortname = os.path.basename(name)
                if shortname.startswith("lib"):
                    shortname = shortname.split("-")[0]
                shortmaps += [(start, end, perm, shortname)]

            count = len(result)
            if display != 0:
                count = min(count, display)
            text += "Found %d results, display max %d items:\n" % (len(result), count)
            for (addr, v) in result[:count]:
                vmrange = self.get_vmrange(addr, shortmaps)
                maxlen = max(maxlen, len(vmrange[3]))

            for (addr, v) in result[:count]:
                vmrange = self.get_vmrange(addr, shortmaps)
                chain = self.examine_mem_reference(addr)
                text += "%s : %s" % (vmrange[3].rjust(maxlen), format_reference_chain(chain) + "\n")

        return text


    ##########################
    #     Exploit Helpers    #
    ##########################
    @memoized
    def elfentry(self):
        """
        Get entry point address of debugged ELF file

        Returns:
            - entry address (Int)
        """
        out = self.execute_redirect("info files")
        p = re.compile("Entry point: ([^\s]*)")
        if out:
            m = p.search(out)
            if m:
                return to_int(m.group(1))
        return None

    @memoized
    def elfheader(self, name=None):
        """
        Get headers information of debugged ELF file

        Args:
            - name: specific header name (String)

        Returns:
            - dictionary of headers {name(String): (start(Int), end(Int), type(String))}
        """
        elfinfo = {}
        elfbase = 0
        if self.getpid():
            binmap = self.get_vmmap("binary")
            elfbase = binmap[0][0] if binmap else 0

        out = self.execute_redirect("maintenance info sections")
        if not out:
            return {}

        p = re.compile("\s*(0x[^-]*)->(0x[^ ]*) at (.*):\s*([^ ]*)\s*(.*)")
        matches = p.findall(out)

        for (start, end, offset, hname, attr) in matches:
            start, end, offset = to_int(start), to_int(end), to_int(offset)
            # skip unuseful header
            if start < offset:
                continue
            # if PIE binary, update with runtime address
            if start < elfbase:
                start += elfbase
                end += elfbase

            if "CODE" in attr:
                htype = "code"
            elif "READONLY" in attr:
                htype = "rodata"
            else:
                htype = "data"

            elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    @memoized
    def elfsymbols(self, pattern=None):
        """
        Get all non-debugging symbol information of debugged ELF file

        Returns:
            - dictionary of (address(Int), symname(String))
        """
        headers = self.elfheader()
        if ".plt" not in headers: # static binary
            return {}

        binmap = self.get_vmmap("binary")
        elfbase = binmap[0][0] if binmap else 0

        # get the .dynstr header
        headers = self.elfheader()
        if ".dynstr" not in headers:
            return {}
        (start, end, _) = headers[".dynstr"]
        mem = self.dumpmem(start, end)
        if not mem and self.getfile():
            fd = open(self.getfile())
            fd.seek(start, 0)
            mem = fd.read(end-start)
            fd.close()

        # Convert names into strings
        dynstrings = [name.decode('utf-8') for name in mem.split(b"\x00")]

        if pattern:
            dynstrings = [s for s in dynstrings if re.search(pattern, s)]

        # get symname@plt info
        symbols = {}
        for symname in dynstrings:
            if not symname: continue
            symname += "@plt"
            out = self.execute_redirect("info functions %s" % symname)
            if not out: continue
            m = re.findall(".*(0x[^ ]*)\s*%s" % re.escape(symname), out)
            for addr in m:
                addr = to_int(addr)
                if self.is_address(addr, binmap):
                    if symname not in symbols:
                        symbols[symname] = addr
                        break

        # if PIE binary, update with runtime address
        for (k, v) in symbols.items():
            if v < elfbase:
                symbols[k] = v + elfbase

        return symbols

    @memoized
    def elfsymbol(self, symname=None):
        """
        Get non-debugging symbol information of debugged ELF file

        Args:
            - name: target function name (String), special cases:
                + "data": data transfer functions
                + "exec": exec helper functions

        Returns:
            - if exact name is not provided: dictionary of tuple (symname, plt_entry)
            - if exact name is provided: dictionary of tuple (symname, plt_entry, got_entry, reloc_entry)
        """
        datafuncs = ["printf", "puts", "gets", "cpy"]
        execfuncs = ["system", "exec", "mprotect", "mmap", "syscall"]
        result = {}
        if not symname or symname in ["data", "exec"]:
            symbols = self.elfsymbols()
        else:
            symbols = self.elfsymbols(symname)

        if not symname:
            result = symbols
        else:
            sname = symname.replace("@plt", "") + "@plt"
            if sname in symbols:
                plt_addr = symbols[sname]
                result[sname] = plt_addr # plt entry
                out = self.get_disasm(plt_addr, 2)
                for line in out.splitlines():
                    if "jmp" in line:
                        addr = to_int("0x" + line.strip().rsplit("0x")[-1].split()[0])
                        result[sname.replace("@plt","@got")] = addr # got entry
                    if "push" in line:
                        addr = to_int("0x" + line.strip().rsplit("0x")[-1])
                        result[sname.replace("@plt","@reloc")] = addr # reloc offset
            else:
                keywords = [symname]
                if symname == "data":
                    keywords = datafuncs
                if symname == "exec":
                    keywords = execfuncs
                for (k, v) in symbols.items():
                    for f in keywords:
                        if f in k:
                            result[k] = v

        return result

    @memoized
    def main_entry(self):
        """
        Get address of main function of stripped ELF file

        Returns:
            - main function address (Int)
        """
        refs = self.xrefs("__libc_start_main@plt")
        if refs:
            inst = self.prev_inst(refs[0][0])
            if inst:
                addr = re.search(".*(0x.*)", inst[0][1])
                if addr:
                    return to_int(addr.group(1))
        return None

    @memoized
    def readelf_header(self, filename, name=None):
        """
        Get headers information of an ELF file using 'readelf'

        Args:
            - filename: ELF file (String)
            - name: specific header name (String)

        Returns:
            - dictionary of headers (name(String), value(Int)) (Dict)
        """
        elfinfo = {}
        vmap = self.get_vmmap(filename)
        elfbase = vmap[0][0] if vmap else 0
        out = execute_external_command("%s -W -S %s" % (config.READELF, filename))
        if not out:
            return {}
        p = re.compile(".*\[.*\] (\.[^ ]*) [^0-9]* ([^ ]*) [^ ]* ([^ ]*)(.*)")
        matches = p.findall(out)
        if not matches:
            return result

        for (hname, start, size, attr) in matches:
            start, end = to_int("0x"+start), to_int("0x"+start) + to_int("0x"+size)
            # if PIE binary or DSO, update with runtime address
            if start < elfbase:
                start += elfbase
            if end < elfbase:
                end += elfbase

            if "X" in attr:
                htype = "code"
            elif "W" in attr:
                htype = "data"
            else:
                htype = "rodata"
            elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    @memoized
    def elfheader_solib(self, solib=None, name=None):
        """
        Get headers information of Shared Object Libraries linked to target

        Args:
            - solib: shared library name (String)
            - name: specific header name (String)

        Returns:
            - dictionary of headers {name(String): start(Int), end(Int), type(String))
        """
        # hardcoded ELF header type
        header_type = {"code": [".text", ".fini", ".init", ".plt", "__libc_freeres_fn"],
            "data": [".dynamic", ".data", ".ctors", ".dtors", ".jrc", ".got", ".got.plt",
                    ".bss", ".tdata", ".tbss", ".data.rel.ro", ".fini_array",
                    "__libc_subfreeres", "__libc_thread_subfreeres"]
        }

        @memoized
        def _elfheader_solib_all():
            out = self.execute_redirect("info files")
            if not out:
                return None

            p = re.compile("[^\n]*\s*(0x[^ ]*) - (0x[^ ]*) is (\.[^ ]*) in (.*)")
            soheaders = p.findall(out)

            result = []
            for (start, end, hname, libname) in soheaders:
                start, end = to_int(start), to_int(end)
                result += [(start, end, hname, os.path.realpath(libname))] # tricky, return the realpath version of libraries
            return result

        elfinfo = {}

        headers = _elfheader_solib_all()
        if not headers:
            return {}

        if solib is None:
            return headers

        vmap = self.get_vmmap(solib)
        elfbase = vmap[0][0] if vmap else 0

        for (start, end, hname, libname) in headers:
            if solib in libname:
                # if PIE binary or DSO, update with runtime address
                if start < elfbase:
                    start += elfbase
                if end < elfbase:
                    end += elfbase
                # determine the type
                htype = "rodata"
                if hname in header_type["code"]:
                    htype = "code"
                elif hname in header_type["data"]:
                    htype = "data"
                elfinfo[hname.strip()] = (start, end, htype)

        result = {}
        if name is None:
            result = elfinfo
        else:
            if name in elfinfo:
                result[name] = elfinfo[name]
            else:
                for (k, v) in elfinfo.items():
                    if name in k:
                        result[k] = v
        return result

    def checksec(self, filename=None):
        """
        Check for various security options of binary (ref: http://www.trapkit.de/tools/checksec.sh)

        Args:
            - file: path name of file to check (String)

        Returns:
            - dictionary of (setting(String), status(Int)) (Dict)
        """
        result = {}
        result["RELRO"] = 0
        result["CANARY"] = 0
        result["NX"] = 1
        result["PIE"] = 0
        result["FORTIFY"] = 0

        if filename is None:
            filename = self.getfile()

        if not filename:
            return None

        out =  execute_external_command("%s -W -a \"%s\" 2>&1" % (config.READELF, filename))
        if "Error:" in out:
            return None

        for line in out.splitlines():
            if "GNU_RELRO" in line:
                result["RELRO"] |= 2
            if "BIND_NOW" in line:
                result["RELRO"] |= 1
            if "__stack_chk_fail" in line:
                result["CANARY"] = 1
            if "GNU_STACK" in line and "RWE" in line:
                result["NX"] = 0
            if "Type:" in line and "DYN (" in line:
                result["PIE"] = 4 # Dynamic Shared Object
            if "(DEBUG)" in line and result["PIE"] == 4:
                result["PIE"] = 1
            if "_chk@" in line:
                result["FORTIFY"] = 1

        if result["RELRO"] == 1:
            result["RELRO"] = 0 # ? | BIND_NOW + NO GNU_RELRO = NO PROTECTION
        # result["RELRO"] == 2 # Partial | NO BIND_NOW + GNU_RELRO
        # result["RELRO"] == 3 # Full | BIND_NOW + GNU_RELRO
        return result

    def _verify_rop_gadget(self, start, end, depth=5):
        """
        Verify ROP gadget code from start to end with max number of instructions

        Args:
            - start: start address (Int)
            - end: end addres (Int)
            - depth: number of instructions (Int)

        Returns:
            - list of valid gadgets (address(Int), asmcode(String))
        """

        result = []
        valid = 0
        out = self.execute_redirect("disassemble 0x%x, 0x%x" % (start, end+1))
        if not out:
            return []

        code = out.splitlines()[1:-1]
        for line in code:
            if "bad" in line:
                return []
            (addr, code) = line.strip().split(":", 1)
            addr = to_int(addr.split()[0])
            result += [(addr, " ".join(code.strip().split()))]
            if "ret" in code:
                return result
            if len(result) > depth:
                break

        return []

    @memoized
    def search_asm(self, start, end, asmcode, rop=0):
        """
        Search for ASM instructions in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - asmcode: assembly instruction (String)
                + multiple instructions are separated by ";"
                + wildcard ? supported, will be replaced by registers or multi-bytes

        Returns:
            - list of (address(Int), hexbyte(String))
        """
        wildcard = asmcode.count('?')
        magic_bytes = ["0x00", "0xff", "0xdead", "0xdeadbeef", "0xdeadbeefdeadbeef"]

        ops = [x for x in asmcode.split(';') if x]
        def buildcode(code=b"", pos=0, depth=0):
            if depth == wildcard and pos == len(ops):
                yield code
                return

            c = ops[pos].count('?')
            if c > 2: return
            elif c == 0:
                asm = self.assemble(ops[pos])
                if asm:
                    for code in buildcode(code + asm, pos+1, depth):
                        yield code
            else:
                save = ops[pos]
                for regs in REGISTERS.values():
                    for reg in regs:
                        ops[pos] = save.replace("?", reg, 1)
                        for asmcode_reg in buildcode(code, pos, depth+1):
                            yield asmcode_reg
                for byte in magic_bytes:
                    ops[pos] = save.replace("?", byte, 1)
                    for asmcode_mem in buildcode(code, pos, depth+1):
                        yield asmcode_mem
                ops[pos] = save

        searches = []

        def decode_hex_escape(str_):
            """Decode string as hex and escape for regex"""
            return re.escape(codecs.decode(str_, 'hex'))

        for machine_code in buildcode():
            search = re.escape(machine_code)
            search = search.replace(decode_hex_escape(b"dead"), b"..")\
                .replace(decode_hex_escape(b"beef"), b"..")\
                .replace(decode_hex_escape(b"00"), b".")\
                .replace(decode_hex_escape(b"ff"), b".")

            if rop and 'ret' not in asmcode:
                search += b".{0,24}\\xc3"
            searches.append(search)

        if not searches:
            warning_msg("invalid asmcode: '%s'" % asmcode)
            return []

        search = b"(?=(" + b"|".join(searches) + b"))"
        candidates = self.searchmem(start, end, search)

        if rop:
            result = {}
            for (a, v) in candidates:
                gadget = self._verify_rop_gadget(a, a+len(v)//2 - 1)
                # gadget format: [(address, asmcode), (address, asmcode), ...]
                if gadget != []:
                    blen = gadget[-1][0] - gadget[0][0] + 1
                    bytes = v[:2*blen]
                    asmcode_rs = "; ".join([c for _, c in gadget])
                    if re.search(re.escape(asmcode).replace("\ ",".*").replace("\?",".*"), asmcode_rs)\
                        and a not in result:
                        result[a] = (bytes, asmcode_rs)
            result = list(result.items())
        else:
            result = []
            for (a, v) in candidates:
                asmcode = self.execute_redirect("disassemble 0x%x, 0x%x" % (a, a+(len(v)//2)))
                if asmcode:
                    asmcode = "\n".join(asmcode.splitlines()[1:-1])
                    matches = re.findall(".*:([^\n]*)", asmcode)
                    result += [(a, (v, ";".join(matches).strip()))]

        return result

    def dumprop(self, start, end, keyword=None, depth=5):
        """
        Dump unique ROP gadgets in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - keyword: to match start of gadgets (String)

        Returns:
            - dictionary of (address(Int), asmcode(String))
        """

        EXTRA_WORDS = ["BYTE ", " WORD", "DWORD ", "FWORD ", "QWORD ", "PTR ", "FAR "]
        result = {}
        mem = self.dumpmem(start, end)
        if mem is None:
            return {}

        if keyword:
            search = keyword
        else:
            search = ""

        if len(mem) > 20000: # limit backward depth if searching in large mem
            depth = 3
        found = re.finditer(b"\xc3", mem)
        found = list(found)
        for m in found:
            idx = start+m.start()
            for i in range(1, 24):
                gadget = self._verify_rop_gadget(idx-i, idx, depth)
                if gadget != []:
                    k = "; ".join([v for (a, v) in gadget])
                    if k.startswith(search):
                        for w in EXTRA_WORDS:
                            k = k.replace(w, "")
                        if k not in result:
                            result[k] = gadget[0][0]
        return result

    def common_rop_gadget(self, mapname=None):
        """
        Get common rop gadgets in binary: ret, popret, pop2ret, pop3ret, add [mem] reg, add reg [mem]

        Returns:
            - dictionary of (gadget(String), address(Int))
        """

        def _valid_register_opcode(bytes_):
            if not bytes_:
                return False

            for c in bytes_iterator(bytes_):
                if ord(c) not in list(range(0x58, 0x60)):
                    return False
            return True

        result = {}
        if mapname is None:
            mapname = "binary"
        maps = self.get_vmmap(mapname)
        if maps is None:
            return result

        for (start, end, _, _) in maps:
            if not self.is_executable(start, maps): continue

            mem = self.dumpmem(start, end)
            found = self.searchmem(start, end, b"....\xc3", mem)
            for (a, v) in found:
                v = codecs.decode(v, 'hex')
                if "ret" not in result:
                    result["ret"] = a+4
                if "leaveret" not in result:
                    if v[-2] == "\xc9":
                        result["leaveret"] = a+3
                if "popret" not in result:
                    if _valid_register_opcode(v[-2:-1]):
                        result["popret"] = a+3
                if "pop2ret" not in result:
                    if _valid_register_opcode(v[-3:-1]):
                        result["pop2ret"] = a+2
                if "pop3ret" not in result:
                    if _valid_register_opcode(v[-4:-1]):
                        result["pop3ret"] = a+1
                if "pop4ret" not in result:
                    if _valid_register_opcode(v[-5:-1]):
                        result["pop4ret"] = a

            # search for add esp, byte 0xNN
            found = self.searchmem(start, end, b"\x83\xc4([^\xc3]){0,24}\xc3", mem)
            # search for add esp, 0xNNNN
            found += self.searchmem(start, end, b"\x81\xc4([^\xc3]){0,24}\xc3", mem)
            for (a, v) in found:
                if v.startswith(b"81"):
                    offset = to_int("0x" + codecs.encode(codecs.decode(v, 'hex')[2:5][::-1], 'hex').decode('utf-8'))
                elif v.startswith(b"83"):
                    offset = to_int("0x" + v[4:6].decode('utf-8'))
                gg = self._verify_rop_gadget(a, a+len(v)//2-1)
                for (_, c) in gg:
                    if "pop" in c:
                        offset += 4
                gadget = "addesp_%d" % offset
                if gadget not in result:
                    result[gadget] = a

        return result

    def search_jmpcall(self, start, end, regname=None):
        """
        Search memory for jmp/call reg instructions

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - reg: register name (String)

        Returns:
            - list of (address(Int), instruction(String))
        """

        result = []
        REG = {0: "eax", 1: "ecx", 2: "edx", 3: "ebx", 4: "esp", 5: "ebp", 6: "esi", 7:"edi"}
        P2REG = {0: "[eax]", 1: "[ecx]", 2: "[edx]", 3: "[ebx]", 6: "[esi]", 7:"[edi]"}
        OPCODE = {0xe: "jmp", 0xd: "call"}
        P2OPCODE = {0x1: "call", 0x2: "jmp"}
        JMPREG = [b"\xff" + bytes_chr(i) for i in range(0xe0, 0xe8)]
        JMPREG += [b"\xff" + bytes_chr(i) for i in range(0x20, 0x28)]
        CALLREG = [b"\xff" + bytes_chr(i) for i in range(0xd0, 0xd8)]
        CALLREG += [b"\xff" + bytes_chr(i) for i in range(0x10, 0x18)]
        JMPCALL = JMPREG + CALLREG

        if regname is None:
            regname = ""
        regname = regname.lower()
        pattern = re.compile(b'|'.join(JMPCALL).replace(b' ', b'\ '))
        mem = self.dumpmem(start, end)
        found = pattern.finditer(mem)
        (arch, bits) = self.getarch()
        for m in list(found):
            inst = ""
            addr = start + m.start()
            opcode = codecs.encode(m.group()[1:2], 'hex')
            type = int(opcode[0:1], 16)
            reg = int(opcode[1:2], 16)
            if type in OPCODE:
                inst = OPCODE[type] + " " + REG[reg]

            if type in P2OPCODE and reg in P2REG:
                inst = P2OPCODE[type] + " " + P2REG[reg]

            if inst != "" and regname[-2:] in inst.split()[-1]:
                if bits == 64:
                    inst = inst.replace("e", "r")
                result += [(addr, inst)]

        return result

    def search_substr(self, start, end, search, mem=None):
        """
        Search for substrings of a given string/number in memory

        Args:
            - start: start address (Int)
            - end: end address (Int)
            - search: string to search for (String)
            - mem: cached memory (raw bytes)

        Returns:
            - list of tuple (substr(String), address(Int))
        """
        def substr(s1, s2):
            "Search for a string in another string"
            s1 = to_binary_string(s1)
            s2 = to_binary_string(s2)
            i = 1
            found = 0
            while i <= len(s1):
                if s2.find(s1[:i]) != -1:
                    found = 1
                    i += 1
                    if s1[:i-1][-1:] == b"\x00":
                        break
                else:
                    break
            if found == 1:
                return i-1
            else:
                return -1

        result = []
        if end < start:
            start, end = end, start

        if mem is None:
            mem = self.dumpmem(start, end)

        if search[:2] == "0x": # hex number
            search = search[2:]
            if len(search) %2 != 0:
                search = "0" + search
            search = codecs.decode(search, 'hex')[::-1]
        search = to_binary_string(decode_string_escape(search))
        while search:
            l = len(search)
            i = substr(search, mem)
            if i != -1:
                sub = search[:i]
                addr = start + mem.find(sub)
                if not check_badchars(addr):
                    result.append((sub, addr))
            else:
                result.append((search, -1))
                return result
            search = search[i:]
        return result


    ##############################
    #   ROP Payload Generation   #
    ##############################
    def payload_copybytes(self, target=None, data=None, template=0):
        """
        Suggest function for ret2plt exploit and generate payload for it

        Args:
            - target: address to copy data to (Int)
            - data: (String)
        Returns:
            - python code template (String)
        """
        result = ""
        funcs = ["strcpy", "sprintf", "strncpy", "snprintf", "memcpy"]

        symbols = self.elfsymbols()
        transfer = ""
        for f in funcs:
            if f+"@plt" in symbols:
                transfer = f
                break
        if transfer == "":
            warning_msg("No copy function available")
            return None

        headers = self.elfheader()
        start = min([v[0] for (k, v) in headers.items() if v[0] > 0])
        end = max([v[1] for (k, v) in headers.items() if v[2] != "data"])
        symbols = self.elfsymbol(transfer)
        if not symbols:
            warning_msg("Unable to find symbols")
            return None

        plt_func = transfer + "_plt"
        plt_addr = symbols[transfer+"@plt"]
        gadgets = self.common_rop_gadget()
        function_template = "\n".join([
            "popret = 0x%x" % gadgets["popret"],
            "pop2ret = 0x%x" % gadgets["pop2ret"],
            "pop3ret = 0x%x" % gadgets["pop3ret"],
            "def %s_payload(target, bytes):" % transfer,
            "    %s = 0x%x" % (plt_func, plt_addr),
            "    payload = []",
            "    offset = 0",
            "    for (str, addr) in bytes:",
            "",
            ])
        if "ncp" in transfer or "mem" in transfer: # memcpy() style
            function_template += "\n".join([
                "        payload += [%s, pop3ret, target+offset, addr, len(str)]" % plt_func,
                "        offset += len(str)",
                ])
        elif "snp" in transfer: # snprintf()
            function_template += "\n".join([
                "        payload += [%s, pop3ret, target+offset, len(str)+1, addr]" % plt_func,
                "        offset += len(str)",
                ])
        else:
            function_template += "\n".join([
            "        payload += [%s, pop2ret, target+offset, addr]" % plt_func,
            "        offset += len(str)",
            ])
        function_template += "\n".join(["",
            "    return payload",
            "",
            "payload = []"
            ])

        if target is None:
            if template != 0:
                return function_template
            else:
                return ""

        #text = "\n_payload = []\n"
        text = "\n"
        mem = self.dumpmem(start, end)
        bytes = self.search_substr(start, end, data, mem)

        if to_int(target) is not None:
            target = to_hex(target)
        text += "# %s <= %s\n" % (target, repr(data))
        if not bytes:
            text += "***Failed***\n"
        else:
            text += "bytes = [\n"
            for (s, a) in bytes:
                if a != -1:
                    text += "    (%s, %s),\n" % (repr(s), to_hex(a))
                else:
                    text += "    (%s, ***Failed***),\n" % repr(s)
            text += "\n".join([
                "]",
                "payload += %s_payload(%s, bytes)" % (transfer, target),
                "",
                ])

class Alias(gdb.Command):
    """
    Generic alias, create short command names
    This doc should be changed dynamically
    """
    def __init__(self, alias, command, shorttext=1):
        (cmd, opt) = (command + " ").split(" ", 1)
        if cmd == "peda" or cmd == "pead":
            cmd = opt.split(" ")[0]
        if not shorttext:
            self.__doc__ = pedacmd._get_helptext(cmd)
        else:
            self.__doc__ = green("Alias for '%s'" % command)
        self._command = command
        self._alias = alias
        super(Alias, self).__init__(alias, gdb.COMMAND_NONE)

    def invoke(self, args, from_tty):
        self.dont_repeat()
        gdb.execute("%s %s" %(self._command, args))

    def complete(self, text, word):
        completion = []
        cmd = self._command.split("peda ")[1]
        for opt in getattr(pedacmd, cmd).options: # list of command's options
            if text in opt and opt not in completion:
                completion += [opt]
        if completion != []:
            return completion
        if cmd in ["set", "show"] and text.split()[0] in ["option"]:
            opname = [x for x in config.OPTIONS.keys() if x.startswith(word.strip())]
            if opname != []:
                completion = opname
            else:
                completion = list(config.OPTIONS.keys())
        return completion
