#!/usr/bin/python3

import hashlib

DEFAULT_BLOCKSIZE=2048

##############################
#### Checksums and Hashes ####
##############################


class RollSum(object):
	def __init__(self):
		self.count = 0
		self.A = 0
		self.B = 0
	
	def rotate(self, inch, outch):
		self.A = (self.A + inch - outch) % 65536
		self.B = (self.B + self.A - (self.count * (outch + 31))) % 65536

	def rollin(self, inch):
		self.A = (self.A + inch + 31) % 65536
		self.B = (self.B + self.A) % 65536
		self.count += 1

	def rollout(self, outch):
		self.A = (self.A - outch) % 65536
		self.B = (self.B - (self.count * (outch + 31))) % 65536
		self.count -= 1

	def sum(self):
		return (self.B << 16) | self.A

def faster_rollsum(data):
	A = 0
	B = 0
	for d in data:
		A += d + 31
		B += A
	return (A & 0xffff) | ((B & 0xffff) * 65536)
		
def md4(data):
	ctx = hashlib.new('md4')
	ctx.update(data)
	return ctx.digest()


#########################
#### Network Packets ####
#########################


class Signature(object):
	def __init__(self, rollsum, md4sum, offset):
		self.rollsum = rollsum
		self.md4sum = md4sum
		self.offset = offset

class CopyChange(object):
	def __init__(self, offset, length):
		self.offset = offset
		self.length = length

	def compose(self, fd):
		fd.seek(self.offset)
		ret = fd.read(self.length)
		assert(len(ret) == self.length)
		return ret

class LiteralChange(object):
	def __init__(self, data):
		self.data = data

	def compose(self, _fd):
		return self.data


#################
#### Actions ####
#################


def generate_signatures(fobj, blocksize=DEFAULT_BLOCKSIZE):
	"""generate signatures for each block in fobj"""
	offset = 0

	while True:
		buf = fobj.read(blocksize) # Assuming blocking mode
		if len(buf) == 0:
			return
		yield Signature(faster_rollsum(buf), md4(buf), offset)
		offset += blocksize

def generate_delta(fobj, signatures, blocksize=DEFAULT_BLOCKSIZE):
	"""Given a file object and signatures from another file,
	   generate a set of deltas (LiteralChange / CopyChange)"""
	buf = fobj.read() # Just read the whole damn file into memory

	sigs = {}
	for s in signatures:
		if s.rollsum in sigs:
			sigs[s.rollsum][s.md4sum] = s.offset
		else:
			sigs[s.rollsum] = { s.md4sum: s.offset }

	rs = RollSum()
	if len(buf) > blocksize:
		# Prime the rolling checksum
		for i in range(blocksize):
			rs.rollin(buf[i])

	offset = 0
	while offset+blocksize < len(buf):
		# Plow through the data, byte at a time
		try:
			md4_table = sigs[rs.sum()]
			md = md4(buf[offset:offset+blocksize])
			file_offset = md4_table[md]
			if offset > 0:
				yield LiteralChange(buf[:offset])
			yield CopyChange(file_offset, blocksize)
			buf = buf[offset+blocksize:]
			offset = 0
		except KeyError:
			rs.rotate(buf[offset+blocksize], buf[offset])
			offset += 1

	while offset < len(buf):
		# See if the last block is still at the end of file
		try:
			md4_table = sigs[rs.sum()]
			md = md4(buf[offset:])
			file_offset = md4_table[md]
			if offset > 0:
				yield LiteralChange(buf[:offset])
			yield CopyChange(file_offset, blocksize)
			return
		except KeyError:
			rs.rollout(buf[offset])
			offset += 1

	# Eh, have the data then
	yield LiteralChange(buf)

def apply_delta(origfd, delta, outfd):
	"""Given the original file (seekable FD) and the delta, write resulting file to outfd"""
	for change in delta:
		outfd.write(change.compose(origfd))

def main():
	import sys
	import os

	if len(sys.argv) != 4:
		print("Usage: {0:s} <origfile> <changedfile> <syncedfile>".format(sys.argv[0]), file=sys.stderr)
		sys.exit(1)
	if os.path.exists(sys.argv[3]):
		print("Error: syncedfile already exists", file=sys.stderr)
		sys.exit(1)
	sigs = generate_signatures(open(sys.argv[1], "rb"))
	delta = generate_delta(open(sys.argv[2], "rb"), sigs)
	apply_delta(open(sys.argv[1], "rb"), delta, open(sys.argv[3], "wb"))


if __name__ == "__main__":
	main()
