class Ip4Address(object):
	def __init__(self, buf):
		self.address = buf
		self.address_string = ".".join("{:d}".format(byte) for byte in buf)

	def __bytes__(self):
		return bytes(self.address)


	def __eq__(self, other):
		return self.address == other.address


	def __repr__(self):
		return self.address_string
