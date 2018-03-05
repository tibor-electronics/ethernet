class Ip4Address(object):
	def __init__(self, buf):
		self.address = buf
		self.address_string = ".".join("{:d}".format(byte) for byte in buf)

	def __repr__(self):
		return self.address_string
