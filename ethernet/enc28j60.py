from ethernet.constants import *
import spidev
import struct


class Enc28j60(object):
	def __init__(self, mac_address, bus=0, device=0):
		self.mac_address = mac_address
		self.bus = bus
		self.device = device
		self.current_bank = -1
		self.spi = None
		self.packet_ptr = RXSTART_INIT


	@property
	def is_link_up(self):
		return self.read_phy(PHSTAT2) & 0x0400 == 0x0400


	@property
	def revision(self):
		return self.read_byte(EREVID)


	def initialize(self):
		# connect and configure device
		self.spi = spidev.SpiDev()
		self.spi.open(self.bus, self.device)
		self.spi.cshigh = False	# active low
		self.spi.threewire = False
		self.spi.lsbfirst = False
		self.spi.loop = False
		self.spi.bits_per_word = 8
		self.spi.max_speed_hz = 2000000

		# reset device
		self.soft_reset()

		# setup buffers
		self.write_short(ERXST, RXSTART_INIT)		# Set receive buffer start address
		self.write_short(ERXRDPT, RXSTART_INIT)		# Set receive pointer address
		self.write_short(ERXND, RXSTOP_INIT)		# Rx End
		self.write_short(ETXST, TXSTART_INIT)		# Tx Start
		self.write_short(ETXND, TXSTOP_INIT)		# Tx End

		# setup MAC
		self.write_byte(MACON1, MACON1_MARXEN | MACON1_TXPAUS | MACON1_RXPAUS)	# Enable MAC receive
		self.write_byte(MACON2, 0x00)											# Bring MAC out of reset
		self.write_op(															# Enable automatic padding to 60bytes and CRC operations
			ENC28J60_BIT_FIELD_SET,
			MACON3,
			MACON3_PADCFG0 | MACON3_TXCRCEN | MACON3_FULDPX | MACON3_FRMLNEN
		)
		# TODO: MACON4
		self.write_short(MAMXFL, MAX_FRAMELEN)									# Do not send packets longer than MAX_FRAMELEN
		self.write_byte(MABBIPG, 0x15)											# Set inter-frame gap (back-to-back)
		#write_short(MAIPG, 0x0C15)												# Set inter-frame gap (non-back-to-back)
		self.write_byte(MAIPG, 0x12)											# Set inter-frame gap (non-back-to-back)

		# set MAC address
		mac_addr = bytes(self.mac_address)
		self.write_byte(MAADR5, mac_addr[0])
		self.write_byte(MAADR4, mac_addr[1])
		self.write_byte(MAADR3, mac_addr[2])
		self.write_byte(MAADR2, mac_addr[3])
		self.write_byte(MAADR1, mac_addr[4])
		self.write_byte(MAADR0, mac_addr[5])

		#write_phy(PHCON2, PHCON2_HDLDIS)	# No loopback of transmitted frames

		self.set_bank(ECON1)													# Switch to bank 0
		self.write_op(ENC28J60_BIT_FIELD_SET, EIE, EIE_INTIE | EIE_PKTIE)		# Enable interrutps
		self.write_op(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_RXEN)				# Enable packet reception


	def set_bank(self, bank):
		bank = bank & BANK_MASK

		if bank != self.current_bank:
			self.current_bank = bank
			self.write_op(ENC28J60_BIT_FIELD_CLR, ECON1, ECON1_BSEL1 | ECON1_BSEL0)
			self.write_op(ENC28J60_BIT_FIELD_SET, ECON1, self.current_bank >> 5)


	def read_op(self, opcode, addr):
		data = [opcode | (addr & ADDR_MASK), 0x00]

		if addr & 0x80:
			data.append(0x00)

		value = self.spi.xfer2(data)
		# log("op {:d} @ {:d} = {}".format(opcode, addr, value))

		return value[-1]


	def read_byte(self, addr):
		self.set_bank(addr)
		return self.read_op(ENC28J60_READ_CTRL_REG, addr)


	def read_buffer(self, size):
		buf = [0] * size
		buf.insert(0, ENC28J60_READ_BUF_MEM)
		data = self.spi.xfer2(buf)

		return data[1:]


	def write_buffer(self, buf):
		data = list(buf)
		data.insert(0, ENC28J60_WRITE_BUF_MEM)
		self.spi.xfer2(data)


	def write_op(self, opcode, addr, data):
		addr = addr & ADDR_MASK

		return self.spi.xfer2([opcode | addr, data])


	def write_byte(self, addr, value):
		self.set_bank(addr)
		self.write_op(ENC28J60_WRITE_CTRL_REG, addr, value)


	def write_short(self, addr, value):
		self.write_byte(addr, value & 0xFF)
		self.write_byte(addr + 1, (value >> 8) & 0xFF)

	def read_phy(self, addr):
		self.write_byte(MIREGADR, addr)
		self.write_byte(MICMD, MICMD_MIIRD)

		while self.read_byte(MISTAT) & MISTAT_BUSY == MISTAT_BUSY:
			pass

		self.write_byte(MICMD, 0x00)

		return self.read_byte(MIRDH) * 256 + self.read_byte(MIRDL)


	def write_phy(self, addr, value):
		self.write_byte(MIREGADR, addr)
		self.write_short(MIWRL, value)
		self.write_short(MIWRH, (value >> 8) & 0xFF)
		
		while self.read_byte(MISTAT) & MISTAT_BUSY == MISTAT_BUSY:
			pass


	def receive_packet(self):
		data = []
		packet_count = self.read_byte(EPKTCNT)

		if packet_count > 0:
			# log("packet count = {:d}".format(packet_count))
			self.write_short(ERDPT, self.packet_ptr)
			header = self.read_buffer(HEADER_SIZE)
			(next_packet, count, status) = struct.unpack("<HHH", bytes(header))
			
			# log("header = {}".format(header))
			# log("next={}, count={}, status={}".format(next_packet, count, status))
			# log("packet_addr={}".format(packet_ptr))

			self.packet_ptr = next_packet
			length = count - 4			# remove CRC

			if status & RECEIVE_OK == RECEIVE_OK:
				data = self.read_buffer(length)
			
			if self.packet_ptr - 1 > RXSTOP_INIT:
				self.write_short(ERXRDPT, RXSTOP_INIT)
			else:
				self.write_short(ERXRDPT, self.packet_ptr - 1)

			self.write_op(ENC28J60_BIT_FIELD_SET, ECON2, ECON2_PKTDEC)

		return data


	def send_packet(self, frame):
		while (self.read_phy(ECON1) & ECON1_TXRTS) == ECON1_TXRTS:
			if self.read_byte(EIR) & EIR_TXERIF == EIR_TXERIF:
				self.write_op(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRST)
				self.write_op(ENC28J60_BIT_FIELD_CLR, ECON1, ECON1_TXRST)

		print("sending packet")
		self.write_short(EWRPT, TXSTART_INIT)						# write pointer to start of buffer
		self.write_short(ETXND, TXSTART_INIT + len(frame))			# set packet size
		self.write_op(ENC28J60_WRITE_BUF_MEM, 0, 0x00)				# use macon3 settings
		self.write_buffer(frame)									# copy frame into buffer
		self.write_op(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRTS)	# send buffer to network

		# Reset the transmit logic problem. See Rev. B4 Silicon Errata point 12.
		if self.read_byte(EIR) & EIR_TXERIF == EIR_TXERIF:
			self.write_op(ENC28J60_BIT_FIELD_CLR, ECON1, ECON1_TXRST)

		print("packet sent")


	def soft_reset(self, ):
		self.write_op(ENC28J60_SOFT_RESET, 0, ENC28J60_SOFT_RESET)

		status = self.read_byte(ESTAT)

		while status & ESTAT_CLKRDY != ESTAT_CLKRDY:
			status = self.read_byte(ESTAT)
