class MacAddress(object):
	def __init__(self, buf):
		self.address = buf
		self.address_string = ":".join("{:02x}".format(byte) for byte in buf)

	def __repr__(self):
		return self.address_string
