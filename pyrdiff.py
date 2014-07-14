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
		self.B = (self.B + self.A - (count * (outch + 31))) % 65536

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
		if buf == '':
			return
		yield Signature(faster_rollsum(buf), md4(buf), offset)
		offset += blocksize

def _find_delta(matches, md):
	for (origmd, origoffset) in matches:
		if origmd == md:
			return origoffset

def generate_delta(fobj, sigs, blocksize=DEFAULT_BLOCKSIZE):
	"""Given a file object and signatures from another file,
	   generate a set of deltas (RawDataChange / FileOffsetChange)"""
	buf = fobj.read() # Just read the whole damn file into memory

	rs = RollSum()
	if len(buf) > blocksize:
		# Prime the rolling checksum
		for i in range(blocksize):
			rs.rollin(buf[i])

	offset = 0
	while offset+blocksize < len(buf):
		# Plow through the data, byte at a time
		if rs.sum() in sigs:
			md = md4(buf[offset:offset+blocksize])
			file_offset = _find_delta(sigs, md)
			if file_offset is not None:
				if offset > 0:
					yield RawDataChange(buf[:offset])
				yield FileOffsetChange(file_offset)
				buf = buf[offset+blocksize:]
				offset = 0
				continue
		offset += 1
		rs.rotate(buf[offset+blocksize], buf[offset-1])

	while offset < len(buf):
		# See if the last block is still at the end of file
		if rs.sum() in sigs:
			md = md4(buf[offset:])
			file_offset = _find_delta(sigs, md)
			if file_offset is not None:
				if offset > 0:
					yield RawDataChange(buf[:offset])
				yield FileOffsetChange(file_offset)
				return
		rs.rollout(buf[offset])
		offset += 1

	# Eh, have the data then
	yield RawDataChange(buf)

def apply_delta(origfd, delta, outfd, blocksize=DEFAULT_BLOCKSIZE):
	"""Given the original file (seekable FD) and the delta, write resulting file to outfd"""
	for change in delta:
		outfd.write(change.compose(origfd, blocksize))

