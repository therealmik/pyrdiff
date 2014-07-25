#!/usr/bin/python

#######
# Experiment: try to make signatures as fast as rdiff
# Results:
#  - Tried using threads.  Slow.
#  - Tried making one function that does most - faster than threads
# Using pypy 2.2.1 this is 3x slower than rdiff in C
#######

import hashlib
import array
import struct
import sys
import os

DEFAULT_BLOCKSIZE=2048
DEFAULT_MD4_TRUNCATION=8 # lol
RS_SIG_MAGIC=0x72730136

def faster_rollsum(data):
        A = 0
        B = 0
        for d in data:
                A += d + 31
                B += A
        return (A & 0xffff) | ((B & 0xffff) * 65536)

def makesigs(infd, outfd, blocksize=DEFAULT_BLOCKSIZE, md4_truncation=DEFAULT_MD4_TRUNCATION):
	md4ctx = hashlib.new('md4')
	pack_rollsum = struct.Struct(">L").pack
	outfd.write(struct.pack(">LLL", RS_SIG_MAGIC, blocksize, md4_truncation))

	while True:
		buf = infd.read(blocksize)
		if len(buf) == 0:
			outfd.flush()
			return
		rs = faster_rollsum(array.array('B', buf))
		ctx = md4ctx.copy()
		ctx.update(buf)
		md4sum = ctx.digest()[:md4_truncation]
		outfd.write(pack_rollsum(rs) + md4sum)

def readfilearg(i, use_stdin=True):
        if len(sys.argv) <= i:
                if use_stdin:
                        return os.fdopen(0, "rb", 16384)
                else:
                        usage()
        else:
                return open(sys.argv[i], "rb", 16384)

def writefilearg(i, use_stdout=True):
        if len(sys.argv) <= i:
                if use_stdout:
                        return os.fdopen(1, "wb", 16384)
                else:
                        usage()
        else:
                return open(sys.argv[i], "wb", 16384)

def main():
	infd = readfilearg(1)
	outfd = writefilearg(2)
	makesigs(infd, outfd)

if __name__ == "__main__":
	main()
