#!/usr/bin/python

from __future__ import print_function

import hashlib
import math
import binascii
import sys
import os
import struct

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

	def set(self, value, count):
		self.A = value & 0xffff
		self.B = (value >> 16) & 0xffff
		self.count = count
	
	def rotate(self, instr, outstr):
		inch = decode_int(instr)
		outch = decode_int(outstr)
		self.A = (self.A + inch - outch) % 65536
		self.B = (self.B + self.A - (self.count * (outch + 31))) % 65536

	def rollin(self, instr):
		inch = decode_int(instr)
		self.A = (self.A + inch + 31) % 65536
		self.B = (self.B + self.A) % 65536
		self.count += 1

	def rollout(self, outstr):
		outch = decode_int(outstr)
		self.A = (self.A - outch) % 65536
		self.B = (self.B - (self.count * (outch + 31))) % 65536
		self.count -= 1

	def sum(self):
		return (self.B << 16) | self.A

def faster_rollsum(data):
	A = 0
	B = 0
	for d in map(decode_int, data):
		A += d + 31
		B += A
	return (A & 0xffff) | ((B & 0xffff) * 65536)
		
def md4(data):
	ctx = hashlib.new('md4')
	ctx.update(data)
	return ctx.digest()


#################
#### Packets ####
#################

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

_integer_encoders = {
	1: struct.Struct(">B").pack,
	2: struct.Struct(">H").pack,
	4: struct.Struct(">L").pack,
	8: struct.Struct(">Q").pack,
}

def encode_int(i, l):
	return _integer_encoders[l](i)

_integer_decoders = {
	1: struct.Struct(">B").unpack,
	2: struct.Struct(">H").unpack,
	4: struct.Struct(">L").unpack,
	8: struct.Struct(">Q").unpack,
}

def decode_int(i, l=1):
	return _integer_decoders[l](i)[0]
	
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
		return encode_int(command, 1) + encode_int(self.offset, offset_len) + encode_int(self.length, length_len)

	def __str__(self):
		return "COPY {0:d} {1:d}".format(self.offset, self.length)

	def __iadd__(self, other):
		# NOTE: "real" rdiff wouldn't merge COPY changes for repeated blocks, because
		# they'd all point to the same offset, rather than contiuous offsets.
		# That makes for bigger delta files for large runs of the same block (eg. a sparse file)
		# Compare debugdelta output for real rdiff vs this tool on dd if=/dev/zero .... to see
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
		return encode_int(command, 1) + encode_int(literal_len, literal_len_length) + self.data

	def __str__(self):
		return "LITERAL [{0:d} bytes]".format(len(self.data))

	def __iadd__(self, other):
		self.data += other.data

######################
#### File formats ####
######################

def write_int(fd, i, nbytes):
	buf = encode_int(i, nbytes)
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
	return decode_int(buf, nbytes)

class Signatures(object):
	def __init__(self, blocksize, md4_truncation):
		self.blocksize = blocksize
		self.md4_truncation = md4_truncation

	def __iter__(self):
		return self.iterator

	@classmethod
	def from_signature_file(cls, fd):
		if read_int(fd, 4) != RS_SIG_MAGIC:
			raise IOError("Invalid signature file magic")
		blocksize = read_int(fd, 4)
		md4_truncation = read_int(fd, 4)
		if md4_truncation > 16 or md4_truncation < 1:
			raise ValueError("Strong sum length must be 1-16 bytes long")
		self = cls(blocksize, md4_truncation)
		self.iterator = self._generate_from_signature_file(fd)
		return self

	@classmethod
	def from_basis_file(cls, fd, blocksize=DEFAULT_BLOCKSIZE, md4_truncation=DEFAULT_MD4_TRUNCATION):
		self = cls(blocksize, md4_truncation)
		self.iterator = self._generate_from_basis(fd)
		return self

	def write(self, fd):
		write_int(fd, RS_SIG_MAGIC, 4)
		write_int(fd, self.blocksize, 4)
		write_int(fd, self.md4_truncation, 4)
		for signature in self.iterator:
			write_int(fd, signature.rollsum, 4)
			fd.write(signature.md4sum[:self.md4_truncation])


	def _generate_from_signature_file(self, fd):
		try:
			offset = 0
			while True:
				rollsum = read_int(fd, 4)
				strong_sum = read_bytes(fd, self.md4_truncation)
				yield Signature(rollsum, strong_sum, offset)
				offset += self.blocksize
		except EOFError:
			pass

	def _generate_from_basis(self, fobj):
		"""generate signatures for each block in fobj"""
		offset = 0

		while True:
			buf = fobj.read(self.blocksize) # Assuming blocking mode
			if len(buf) == 0:
				return
			yield Signature(faster_rollsum(buf), md4(buf)[:self.md4_truncation], offset)
			offset += self.blocksize


class Delta(object):
	def __init__(self, iterator):
		self.iterator = iterator

	def __iter__(self):
		return self.iterator

	def patch(self, origfd, outfd):
		"""Given the original file (seekable FD) and the delta, write resulting file to outfd"""
		for change in iter(self):
			outfd.write(change.compose(origfd))

	def write(self, fd):
		write_int(fd, RS_DELTA_MAGIC, 4)
		for change in self.iterator:
			fd.write(change.serialize())
		write_int(fd, 0, 1) # End

	@classmethod
	def from_delta_file(cls, fd):
		return cls(cls.read_delta_file(fd))
	
	@staticmethod
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

	@classmethod
	def from_signatures(cls, signatures, changedfd):
		return cls(cls._merge_delta(cls._generate_delta(signatures, changedfd)))

	@staticmethod
	def _generate_delta(signatures, changedfd):
		"""Given a file object and signatures from another file,
		   generate a set of deltas (LiteralChange / CopyChange)"""
		buf = changedfd.read() # Just read the whole damn file into memory
		blocksize = signatures.blocksize
		md4_truncation = signatures.md4_truncation

		sigs = {}
		for s in iter(signatures):
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
				count = min(blocksize, len(buf))
				rs.set(faster_rollsum(buf[:count]), count)
				continue

			# Plow through the data, byte at a time
			try:
				md4_table = sigs[rs.sum()]
				md = md4(buf[offset:offset+blocksize])[:md4_truncation]
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

		# Processing the last block is a bit different
		while offset < len(buf):
			# See if the last block is still at the end of file
			try:
				md4_table = sigs[rs.sum()]
				md = md4(buf[offset:])[:md4_truncation]
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

	@staticmethod
	def _merge_delta(generator):
		"""Merge adjacent COPY blocks"""
		prevchange = None
		for change in generator:
			# Merge if we can
			if prevchange.__class__ == change.__class__:
				prevchange += change
			else:
				if prevchange != None:
					yield prevchange
				prevchange = change
		# If the last command was a copy, yield it before StopIteration
		if prevchange is not None:
			yield prevchange

########################
#### High-level API ####
########################

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
		Signatures.from_basis_file(basisfd).write(sigfd)
	elif sys.argv[1] == "delta":
		sigfd = readfilearg(2, False)
		newfilefd = readfilearg(3)
		deltafd = writefilearg(4)
		signatures = Signatures.from_signature_file(sigfd)
		Delta.from_signatures(signatures, newfilefd).write(deltafd)
	elif sys.argv[1] == "patch":
		basisfd = readfilearg(2, False)
		deltafd = readfilearg(3)
		newfilefd = writefilearg(4)
		Delta.from_delta_file(deltafd).patch(basisfd, newfilefd)
	elif sys.argv[1] == "debugdelta":
		for d in iter(Delta.from_delta_file(readfilearg(2))):
			print(str(d))
	elif sys.argv[1] == "debugsigs":
		signatures = Signatures.from_signature_file(readfilearg(2))
		print("SIG HEADER: blocksize={0:d} md4_truncation={1:d}".format(signatures.blocksize, signatures.md4_truncation))
		for s in iter(signatures):
			print(str(s))
	else:
		usage()

if __name__ == "__main__":
	main()
