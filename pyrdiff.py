#!/usr/bin/python3

import hashlib
import math
import binascii
import sys
import os

DEFAULT_BLOCKSIZE=2048
DEFAULT_MD4_TRUNCATION=8 # lol
RS_DELTA_MAGIC=0x72730236
RS_SIG_MAGIC=0x72730136

def log2(i):
	return int(math.log(i, 2))

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

def write_int(fd, i, nbytes):
	buf = i.to_bytes(nbytes, 'big')
	fd.write(buf)

def read_bytes(fd, nbytes):
	buf = fd.read(nbytes)
	if len(buf) == 0:
		raise EOFError()
	if len(buf) != nbytes:
		raise IOError("Unexpected EOF")
	return buf

def read_int(fd, nbytes):
	buf = read_bytes(fd, nbytes)
	return int.from_bytes(buf, 'big')

class SignatureFileReader(object):
	def __init__(self, block_len, strong_sum_len):
		self.block_len = block_len
		self.strong_sum_len = strong_sum_len

	@classmethod
	def open(cls, fd):
		if read_int(fd, 4) != RS_SIG_MAGIC:
			raise IOError("Invalid signature file magic")
		block_len = read_int(fd, 4)
		strong_sum_len = read_int(fd, 4)
		if strong_sum_len > 16 or strong_sum_len < 1:
			raise ValueError("Strong sum length must be 1-16 bytes long")
		self = cls(block_len, strong_sum_len)
		self.readfd = fd
		return self

	def __iter__(self):
		try:
			offset = 0
			while True:
				rollsum = read_int(self.readfd, 4)
				strong_sum = read_bytes(self.readfd, self.strong_sum_len)
				yield Signature(rollsum, strong_sum, offset)
				offset += self.block_len
		except EOFError:
			pass

def write_signature_file(fd, block_len, strong_sum_len, signatures):
	write_int(fd, RS_SIG_MAGIC, 4)
	write_int(fd, block_len, 4)
	write_int(fd, strong_sum_len, 4)

	for signature in signatures:
		write_int(fd, signature.rollsum, 4)
		fd.write(signature.md4sum[:strong_sum_len])

def read_delta_file(fd):
	if read_int(fd, 4) != RS_DELTA_MAGIC:
		raise IOError("Invalid delta file magic")

	while True:
		command = read_int(fd, 1)
		if command == 0: # RS_OP_END
			return
		elif command >= 0x41 and command <= 0x44:
			literal_len_len = 1 << (command - 0x41)
			literal_len = read_int(fd, literal_len_len)
			yield LiteralChange(read_bytes(fd, literal_len))
		elif command >= 0x45 and command <= 0x54:
			command -= 0x45
			offset_len = 1 << (command // 4)
			length_len = 1 << (command % 4)
			offset = read_int(fd, offset_len)
			length = read_int(fd, length_len)
			yield CopyChange(offset, length)
		else:
			raise ValueError("Invalid command: " + hex(command))

def write_delta_file(fd, changes):
	write_int(fd, RS_DELTA_MAGIC, 4)
	for change in changes:
		fd.write(change.serialize())
	write_int(fd, 0, 1) # End

class Signature(object):
	def __init__(self, rollsum, md4sum, offset):
		self.rollsum = rollsum
		self.md4sum = md4sum
		self.offset = offset

	def __str__(self):
		return "SIGNATURE: {0:08x} {1!r} {2!r}".format(self.rollsum, binascii.hexlify(self.md4sum), self.offset)

def byte_length(i):
	bit_len = i.bit_length()
	if bit_len <= 8:
		return 1
	elif bit_len <= 16:
		return 2
	elif bit_len <= 32:
		return 4
	elif bit_len <= 64:
		return 8
	else:
		raise ValueError("Cannot represent integers > 64bits")

class CopyChange(object):
	def __init__(self, offset, length):
		self.offset = offset
		self.length = length

	def compose(self, fd):
		fd.seek(self.offset)
		ret = fd.read(self.length)
		assert(len(ret) == self.length)
		return ret

	def serialize(self):
		offset_len = byte_length(self.offset)
		length_len = byte_length(self.length)
		command = 0x45 + ( log2(offset_len) * 4 ) + log2(length_len)
		return command.to_bytes(1, 'big') + self.offset.to_bytes(offset_len, 'big') + self.length.to_bytes(length_len, 'big')

	def __str__(self):
		return "COPY {0:d} {1:d}".format(self.offset, self.length)

	def __iadd__(self, other):
		assert(other.offset == self.offset + self.length)
		self.length += other.length
		return self

class LiteralChange(object):
	def __init__(self, data):
		self.data = data

	def compose(self, _fd):
		return self.data

	def serialize(self):
		literal_len = len(self.data)
		literal_len_length = byte_length(literal_len)
		command = 0x41 + log2(literal_len_length)
		return command.to_bytes(1, 'big') + literal_len.to_bytes(literal_len_length, 'big') + self.data

	def __str__(self):
		return "LITERAL [{0:d} bytes]".format(len(self.data))

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

def generate_delta(fobj, signatures, blocksize=DEFAULT_BLOCKSIZE, strong_sum_len = 16):
	"""Given a file object and signatures from another file,
	   generate a set of deltas (LiteralChange / CopyChange)"""
	buf = fobj.read() # Just read the whole damn file into memory

	sigs = {}
	for s in signatures:
		if s.rollsum in sigs:
			if s.md4sum not in sigs[s.rollsum]: # for identical/collision blocks, use only the first, as rdiff does
				sigs[s.rollsum][s.md4sum] = s.offset
		else:
			sigs[s.rollsum] = { s.md4sum: s.offset }

	rs = RollSum()

	offset = 0
	while offset+blocksize < len(buf):
		# Prime the rolling sum
		if rs.count == 0:
			for i in range(min(blocksize, len(buf))):
				rs.rollin(buf[i])
			continue

		# Plow through the data, byte at a time
		try:
			md4_table = sigs[rs.sum()]
			md = md4(buf[offset:offset+blocksize])[:strong_sum_len]
			file_offset = md4_table[md]
			if offset > 0:
				yield LiteralChange(buf[:offset])
			yield CopyChange(file_offset, blocksize)
			buf = buf[offset+blocksize:]
			offset = 0
			rs = RollSum()
		except KeyError:
			rs.rotate(buf[offset+blocksize], buf[offset])
			offset += 1

	while offset < len(buf):
		# See if the last block is still at the end of file
		try:
			md4_table = sigs[rs.sum()]
			md = md4(buf[offset:])[:strong_sum_len]
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

def merge_delta(generator):
	prevcopy = None
	for change in generator:
		# Merge if we can
		if isinstance(prevcopy, CopyChange):
			if isinstance(change, CopyChange):
				prevcopy += change
				continue
		# Ok, we don't need the held COPY
		if prevcopy is not None:
			yield prevcopy
			prevcopy = None

		# Hold on if we have a COPY
		if isinstance(change, CopyChange):
			prevcopy = change
		else:
			yield change

	# If the last command was a copy, yield it before StopIteration
	if prevcopy is not None:
		yield prevcopy

def patch(origfd, delta, outfd):
	"""Given the original file (seekable FD) and the delta, write resulting file to outfd"""
	for change in delta:
		outfd.write(change.compose(origfd))

def usage():
	print("Usage: {0:s} <command> [options ...]".format(sys.argv[0]), file=sys.stderr)
	print("     signature [BASIS [SIGNATURE]]", file=sys.stderr)
	print("     delta SIGNATURE [NEWFILE [DELTA]]", file=sys.stderr)
	print("     patch BASIS [DELTA [NEWFILE]]", file=sys.stderr)
	print(" (optional args replaced with stdin/stdout as appropriate", file=sys.stderr)
	sys.exit(1)

def readfilearg(i, use_stdin=True):
	if len(sys.argv) <= i:
		if use_stdin:
			return os.fdopen(0, "rb")
		else:
			usage()
	else:
		return open(sys.argv[i], "rb")

def writefilearg(i, use_stdout=True):
	if len(sys.argv) <= i:
		if use_stdout:
			return os.fdopen(1, "wb")
		else:
			usage()
	else:
		return open(sys.argv[i], "wb")

def main():
	if len(sys.argv) < 2:
		usage()
	if sys.argv[1] == "signature":
		basisfd = readfilearg(2)
		sigfd = writefilearg(3)
		signatures = generate_signatures(basisfd, DEFAULT_BLOCKSIZE)
		write_signature_file(sigfd, DEFAULT_BLOCKSIZE, DEFAULT_MD4_TRUNCATION, signatures)
	elif sys.argv[1] == "delta":
		sigfd = readfilearg(2, False)
		newfilefd = readfilearg(3)
		deltafd = writefilearg(4)
		signatures = SignatureFileReader.open(sigfd)
		delta = merge_delta(generate_delta(newfilefd, iter(signatures), signatures.block_len, signatures.strong_sum_len))
		write_delta_file(deltafd, delta)
	elif sys.argv[1] == "patch":
		basisfd = readfilearg(2, False)
		delta = read_delta_file(readfilearg(3))
		newfilefd = writefilearg(4)
		patch(basisfd, delta, newfilefd)
	elif sys.argv[1] == "debugdelta":
		delta = read_delta_file(readfilearg(2))
		for d in delta:
			print(str(d))
	elif sys.argv[1] == "debugsigs":
		signatures = SignatureFileReader.open(readfilearg(2))
		print("SIG HEADER: block_len={0:d} strong_sum_len={1:d}".format(signatures.block_len, signatures.strong_sum_len))
		for s in iter(signatures):
			print(str(s))
	else:
		usage()

if __name__ == "__main__":
	main()
