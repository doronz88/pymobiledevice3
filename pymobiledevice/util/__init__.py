from past.builtins import xrange
import glob
import plistlib
import os
import gzip
from optparse import *

try:
    import cPickle
except ImportError:
    import pickle as cPickle
    plistlib.readPlistFromString = plistlib.loads
    plistlib.readPlist = plistlib.load

def read_file(filename):
    f = open(filename, "rb")
    data = f.read()
    f.close()
    return data

def write_file(filename,data):
    f = open(filename, "wb")
    f.write(data)
    f.close()

def makedirs(dirs):
    try:
        os.makedirs(dirs)
    except:
        pass

def getHomePath(foldername, filename):
    home = os.path.expanduser('~')
    folderpath = os.path.join(home, foldername)
    if not os.path.exists(folderpath):
        makedirs(folderpath)
    return os.path.join(folderpath, filename)

def readHomeFile(foldername, filename):
    path = getHomePath(foldername, filename)
    if not os.path.exists(path):
        return None
    return read_file(path)

#return path to HOME+foldername+filename
def writeHomeFile(foldername, filename, data):
    filepath = getHomePath(foldername, filename)
    write_file(filepath, data)
    return filepath

def readPlist(filename):
    return plistlib.readPlist(filename)

def parsePlist(s):
    return plistlib.readPlistFromString(s)

#http://stackoverflow.com/questions/1094841/reusable-library-to-get-human-readable-version-of-file-size
def sizeof_fmt(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%d%s" % (num, x)
        num /= 1024.0

#http://www.5dollarwhitebox.org/drupal/node/84
def convert_bytes(bytes):
    bytes = float(bytes)
    if bytes >= 1099511627776:
        terabytes = bytes / 1099511627776
        size = '%.2fT' % terabytes
    elif bytes >= 1073741824:
        gigabytes = bytes / 1073741824
        size = '%.2fG' % gigabytes
    elif bytes >= 1048576:
        megabytes = bytes / 1048576
        size = '%.2fM' % megabytes
    elif bytes >= 1024:
        kilobytes = bytes / 1024
        size = '%.2fK' % kilobytes
    else:
        size = '%.2fb' % bytes
    return size

def xor_strings(a,b):
    r=""
    for i in xrange(len(a)):
        r+= chr(ord(a[i])^ord(b[i]))
    return r

hex = lambda data: " ".join("%02X" % ord(i) for i in data)
ascii = lambda data: "".join(c if 31 < ord(c) < 127 else "." for c in data)

def hexdump(d):
    for i in xrange(0,len(d),16):
        data = d[i:i+16]
        print("%08X | %s | %s" % (i, hex(data).ljust(47), ascii(data)))

def search_plist(directory, matchDict):
    for p in map(os.path.normpath, glob.glob(directory + "/*.plist")):
        try:
            d = plistlib.readPlist(p)
            ok = True
            for k,v in matchDict.items():
                if d.get(k) != v:
                    ok = False
                    break
            if ok:
                print("Using plist file %s" % p)
                return d
        except:
            continue

def save_pickle(filename,data):
    f = gzip.open(filename,"wb")
    cPickle.dump(data, f, cPickle.HIGHEST_PROTOCOL)
    f.close()

def load_pickle(filename):
    f = gzip.open(filename,"rb")
    data = cPickle.load(f)
    f.close()
    return data


class MultipleOption(Option):
    ACTIONS = Option.ACTIONS + ("extend",)
    STORE_ACTIONS = Option.STORE_ACTIONS + ("extend",)
    TYPED_ACTIONS = Option.TYPED_ACTIONS + ("extend",)
    ALWAYS_TYPED_ACTIONS = Option.ALWAYS_TYPED_ACTIONS + ("extend",)

    def take_action(self, action, dest, opt, value, values, parser):
        if action == "extend":
            values.ensure_value(dest, []).append(value)
        else:
            Option.take_action(self, action, dest, opt, value, values, parser)
