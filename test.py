#!/usr/bin/python3

import sys
import struct
import spidev

from ethernet.ethernet_frame import EthernetFrame
from ethernet.ip_frame import IpFrame
from ethernet.arp_frame import ArpFrame


BANK_MASK = 0x60
ADDR_MASK = 0x1F

ECON1 = 0x1F

# SPI Operation Codes
ENC28J60_READ_CTRL_REG = 0x00
ENC28J60_READ_BUF_MEM = 0x3A
ENC28J60_WRITE_CTRL_REG = 0x40
ENC28J60_WRITE_BUF_MEM = 0x7A
ENC28J60_BIT_FIELD_SET = 0x80
ENC28J60_BIT_FIELD_CLR = 0xA0
ENC28J60_SOFT_RESET = 0xFF

ECON1_BSEL1 = 0x02
ECON1_BSEL0 = 0x01

# The RXSTART_INIT must be zero. See Rev. B4 Silicon Errata point 5.
# Buffer boundaries applied to internal 8K ram
# the entire available packet buffer space is allocated

RXSTART_INIT = 0x0000	# start of RX buffer, room for 2 packets
RXSTOP_INIT = 0x0BFF	# end of RX buffer
TXSTART_INIT = 0x0C00	# start of TX buffer, room for 1 packet
TXSTOP_INIT = 0x11FF	# end of TX buffer

# max frame length which the controller will accept:
# (note: maximum Ethernet frame length would be 1518)
MAX_FRAMELEN = 1500

# all-bank registers
EIE = 0x1B
EIR = 0x1C
ESTAT = 0x1D
ECON2 = 0x1E
ECON1 = 0x1F

# bank 0
ERDPT = 0x00
EWRPT = 0x02
ETXST = 0x04
ETXND = 0x06
ERXST = 0x08
ERXND = 0x0A
ERXRDPT = 0x0C
ERXWRPT = 0x0E
EDMAST = 0x10
EDMAND = 0x12
EDMADST = 0x14
EDMACS = 0x16

# bank 1
EHT0 = (0x00 | 0x20)
EHT1 = (0x01 | 0x20)
EHT2 = (0x02 | 0x20)
EHT3 = (0x03 | 0x20)
EHT4 = (0x04 | 0x20)
EHT5 = (0x05 | 0x20)
EHT6 = (0x06 | 0x20)
EHT7 = (0x07 | 0x20)
EPMM0 = (0x08 | 0x20)
EPMM1 = (0x09 | 0x20)
EPMM2 = (0x0A | 0x20)
EPMM3 = (0x0B | 0x20)
EPMM4 = (0x0C | 0x20)
EPMM5 = (0x0D | 0x20)
EPMM6 = (0x0E | 0x20)
EPMM7 = (0x0F | 0x20)
EPMCS = (0x10 | 0x20)
EPMO = (0x14 | 0x20)
EWOLIE = (0x16 | 0x20)
EWOLIR = (0x17 | 0x20)
ERXFCON = (0x18 | 0x20)
EPKTCNT = (0x19 | 0x20)

# bank 2
MACON1 = (0x00 | 0x40 | 0x80)
MACON2 = (0x01 | 0x40 | 0x80)
MACON3 = (0x02 | 0x40 | 0x80)
MACON4 = (0x03 | 0x40 | 0x80)
MABBIPG = (0x04 | 0x40 | 0x80)
MAIPG = (0x06 | 0x40 | 0x80)
MACLCON1 = (0x08 | 0x40 | 0x80)
MACLCON2 = (0x09 | 0x40 | 0x80)
MAMXFL = (0x0A | 0x40 | 0x80)
MAPHSUP = (0x0D | 0x40 | 0x80)
MICON = (0x11 | 0x40 | 0x80)
MICMD = (0x12 | 0x40 | 0x80)
MIREGADR = (0x14 | 0x40 | 0x80)
MIWRL = (0x16 | 0x40 | 0x80)
MIWRH = (0x17 | 0x40 | 0x80)
MIRDL = (0x18 | 0x40 | 0x80)
MIRDH = (0x19 | 0x40 | 0x80)

# bank 3
MAADR1 = (0x00 | 0x60 | 0x80)
MAADR0 = (0x01 | 0x60 | 0x80)
MAADR3 = (0x02 | 0x60 | 0x80)
MAADR2 = (0x03 | 0x60 | 0x80)
MAADR5 = (0x04 | 0x60 | 0x80)
MAADR4 = (0x05 | 0x60 | 0x80)
EBSTSD = (0x06 | 0x60)
EBSTCON = (0x07 | 0x60)
EBSTCS = (0x08 | 0x60)
MISTAT = (0x0A | 0x60 | 0x80)
EREVID = (0x12 | 0x60)
ECOCON = (0x15 | 0x60)
EFLOCON = (0x17 | 0x60)
EPAUS = (0x18 | 0x60)

# PHY registers
PHCON1 = 0x00
PHSTAT1 = 0x01
PHHID1 = 0x02
PHHID2 = 0x03
PHCON2 = 0x10
PHSTAT2 = 0x11
PHIE = 0x12
PHIR = 0x13
PHLCON = 0x14

# ERXFCON register flags
ERXFCON_BCEN = 0x01
ERXFCON_MCEN = 0x02
ERXFCON_HTEN = 0x04
ERXFCON_MPEN = 0x08
ERXFCON_PMEN = 0x10
ERXFCON_CRCEN = 0x20
ERXFCON_ANDOR = 0x40
ERXFCON_UCEN = 0x80

# ECON1 register flags
ECON1_BSEL0 = 0x01
ECON1_BSEL1 = 0x02
ECON1_RXEN = 0x04
ECON1_TXRTS = 0x08
ECON1_CSUMEN = 0x10
ECON1_DMAST = 0x20
ECON1_RXRST = 0x40
ECON1_TXRST = 0x80

# ECON2 register flags
ECON2_VRPS = 0x08
ECON2_PWRSV = 0x20
ECON2_PKTDEC = 0x40
ECON2_AUTOINC = 0x80

# EIE register flags
EIE_RXERIE = 0x01
EIE_TXERIE = 0x02
EIE_WOLIE = 0x04
EIE_TXIE = 0x08
EIE_LINKIE = 0x10
EIE_DMAIE = 0x20
EIE_PKTIE = 0x40
EIE_INTIE = 0x80

# EIR register flags
EIR_RXERIF = 0x01
EIR_TXERIF = 0x02
EIR_WOLIF  = 0x04
EIR_TXIF   = 0x08
EIR_LINKIF = 0x10
EIR_DMAIF  = 0x20
EIR_PKTIF  = 0x40

# ESTAT register flags
ESTAT_INT     = 0x80
ESTAT_LATECOL = 0x10
ESTAT_RXBUSY  = 0x04
ESTAT_TXABRT  = 0x02
ESTAT_CLKRDY  = 0x01

# PHY PHCON2 register flags
PHCON2_HDLDIS = 0x0100
PHCON2_JABBER = 0x0400
PHCON2_TXDIS  = 0x2000
PHCON2_FRCLINK = 0x4000

#  M ACON1 register flags
MACON1_MARXEN = 0x01
MACON1_PASSALL = 0x02
MACON1_RXPAUS = 0x04
MACON1_TXPAUS = 0x08
MACON1_LOOPBK = 0x10

# MACON2 register flags
MACON2_TFUNRST = 0x01
MACON2_MATXRST = 0x02
MACON2_RFUNRST = 0x04
MACON2_MARXRST = 0x08
MACON2_RNDRST = 0x40
MACON2_MARST = 0x80

# MACON3 register flags
MACON3_FULDPX = 0x01
MACON3_FRMLNEN = 0x02
MACON3_HFRMLEN = 0x04
MACON3_PHDRLEN = 0x08
MACON3_TXCRCEN = 0x10
MACON3_PADCFG0 = 0x20
MACON3_PADCFG1 = 0x40
MACON3_PADCFG2 = 0x80

# MICMD register flags
MICMD_MIIRD = 0x01
MICMD_MIISCAN = 0x02

# MISTAT Register Bit Definitions
MISTAT_BUSY = 0x01
MISTAT_SCAN = 0x02
MISTAT_NVALID = 0x04

HEADER_SIZE = 6

# Status bits
DROP_EVENT = 0x0001
CARRIER_EVENT = 0x0004
CRC_ERROR = 0x0010
LENGTH_CHECK_ERROR = 0x0020
LENGTH_OUT_OF_RANGE = 0x0040
RECEIVE_OK = 0x0080
RECEIVE_MULTICAST = 0x0100
RECEIVE_BROADCAST = 0x0200
DRIBBLE = 0x0400
CONTROL_FRAME = 0x0800
PAUSE_CONTROL_FRAME = 0x1000
UNKNOWN_OPCODE = 0x2000
VLAN_FRAME = 0x4000

current_bank = -1
spi = None
packet_ptr = RXSTART_INIT


def log(message=""):
	print(message)
	sys.stdout.flush()

def set_bank(bank):
	global current_bank

	bank = bank & BANK_MASK

	if bank != current_bank:
		current_bank = bank
		write_op(ENC28J60_BIT_FIELD_CLR, ECON1, ECON1_BSEL1 | ECON1_BSEL0)
		write_op(ENC28J60_BIT_FIELD_SET, ECON1, current_bank >> 5)


def read_op(opcode, addr):
	data = [opcode | (addr & ADDR_MASK), 0x00]

	if addr & 0x80:
		data.append(0x00)

	value = spi.xfer2(data)
	# log("op {:d} @ {:d} = {}".format(opcode, addr, value))

	return value[-1]


def read_byte(addr):
	set_bank(addr)
	return read_op(ENC28J60_READ_CTRL_REG, addr)


def read_buffer(size):
	bfr = [0] * size
	bfr.insert(0, ENC28J60_READ_BUF_MEM)
	data = spi.xfer2(bfr)

	return data[1:]


def write_buffer(buffer):
	data = list(buffer)
	data.insert(0, ENC28J60_WRITE_BUF_MEM)
	spi.xfer2(data)


def write_op(opcode, addr, data):
	addr = addr & ADDR_MASK

	return spi.xfer2([opcode | addr, data])


def write_byte(addr, value):
	set_bank(addr)
	write_op(ENC28J60_WRITE_CTRL_REG, addr, value)


def write_short(addr, value):
	write_byte(addr, value & 0xFF)
	write_byte(addr + 1, (value >> 8) & 0xFF)


def read_phy(addr):
	write_byte(MIREGADR, addr)
	write_byte(MICMD, MICMD_MIIRD)

	while read_byte(MISTAT) & MISTAT_BUSY == MISTAT_BUSY:
		pass

	write_byte(MICMD, 0x00)

	return read_byte(MIRDH) * 256 + read_byte(MIRDL)


def write_phy(addr, value):
	write_byte(MIREGADR, addr)
	write_short(MIWRL, value)
	write_short(MIWRH, (value >> 8) & 0xFF)
	
	while(read_byte(MISTAT) & MISTAT_BUSY):
		pass


def is_link_up():
	return read_phy(PHSTAT2) & 0x0400 == 0x0400


def receive_packet():
	global packet_ptr
	data = []
	packet_count = read_byte(EPKTCNT)


	if packet_count > 0:
		# log("packet count = {:d}".format(packet_count))
		write_short(ERDPT, packet_ptr)
		header = read_buffer(HEADER_SIZE)
		(next_packet, count, status) = struct.unpack("<HHH", bytes(header))
		
		# log("header = {}".format(header))
		# log("next={}, count={}, status={}".format(next_packet, count, status))
		# log("packet_addr={}".format(packet_ptr))

		packet_ptr = next_packet
		length = count - 4			# remove CRC

		if status & RECEIVE_OK == RECEIVE_OK:
			data = read_buffer(length)
		
		if packet_ptr - 1 > RXSTOP_INIT:
			write_short(ERXRDPT, RXSTOP_INIT)
		else:
			write_short(ERXRDPT, packet_ptr - 1)

		write_op(ENC28J60_BIT_FIELD_SET, ECON2, ECON2_PKTDEC)

	return data


def send_packet(frame):
	while (read_phy(ECON1) & ECON1_TXRTS) == ECON1_TXRTS:
		if read_byte(EIR) & EIR_TXERIF == EIR_TXERIF:
			write_op(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRST)
			write_op(ENC28J60_BIT_FIELD_CLR, ECON1, ECON1_TXRST)

	print("sending packet")
	write_short(EWRPT, TXSTART_INIT)						# write pointer to start of buffer
	write_short(ETXND, TXSTART_INIT + len(frame))			# set packet size
	write_op(ENC28J60_WRITE_BUF_MEM, 0, 0x00)				# use macon3 settings
	write_buffer(frame)										# copy frame into buffer
	write_op(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_TXRTS)	# send buffer to network

	# Reset the transmit logic problem. See Rev. B4 Silicon Errata point 12.
	if (read_byte(EIR) & EIR_TXERIF == EIR_TXERIF):
		write_op(ENC28J60_BIT_FIELD_CLR, ECON1, ECON1_TXRST)
	print("packet sent")


def soft_reset():
	write_op(ENC28J60_SOFT_RESET, 0, ENC28J60_SOFT_RESET)

	status = read_byte(ESTAT)

	while (status & ESTAT_CLKRDY) != ESTAT_CLKRDY:
		status = read_byte(ESTAT)


if __name__ == "__main__":
	bus = 0
	device = 0
	mac_addr = [0x02, 0x03, 0x04, 0x05, 0x06, 0x07]
	mac_addr_str = ":".join("{:02x}".format(byte) for byte in mac_addr)
	ip_addr = "10.0.1.254"
	input_mac_filter = "30:9c:23:0d:2d:7f"

	# connect and configure device
	spi = spidev.SpiDev()
	spi.open(bus, device)
	spi.cshigh = False	# active low
	spi.threewire = False
	spi.lsbfirst = False
	spi.loop = False
	spi.bits_per_word = 8
	spi.max_speed_hz = 2000000

	# reset device
	soft_reset()

	# setup buffers
	write_short(ERXST, RXSTART_INIT)		# Set receive buffer start address
	write_short(ERXRDPT, RXSTART_INIT)		# Set receive pointer address
	write_short(ERXND, RXSTOP_INIT)			# Rx End
	write_short(ETXST, TXSTART_INIT)		# Tx Start
	write_short(ETXND, TXSTOP_INIT)			# Tx End

	# setup MAC
	write_byte(MACON1, MACON1_MARXEN | MACON1_TXPAUS | MACON1_RXPAUS)	# Enable MAC receive
	write_byte(MACON2, 0x00)											# Bring MAC out of reset
	write_op(															# Enable automatic padding to 60bytes and CRC operations
		ENC28J60_BIT_FIELD_SET,
		MACON3,
		MACON3_PADCFG0 | MACON3_TXCRCEN | MACON3_FULDPX | MACON3_FRMLNEN
	)
	# TODO: MACON4
	write_short(MAMXFL, MAX_FRAMELEN)									# Do not send packets longer than MAX_FRAMELEN
	write_byte(MABBIPG, 0x15)											# Set inter-frame gap (back-to-back)
	#write_short(MAIPG, 0x0C15)											# Set inter-frame gap (non-back-to-back)
	write_byte(MAIPG, 0x12)											# Set inter-frame gap (non-back-to-back)

	# set MAC address
	write_byte(MAADR5, mac_addr[0])
	write_byte(MAADR4, mac_addr[1])
	write_byte(MAADR3, mac_addr[2])
	write_byte(MAADR2, mac_addr[3])
	write_byte(MAADR1, mac_addr[4])
	write_byte(MAADR0, mac_addr[5])

	#write_phy(PHCON2, PHCON2_HDLDIS)	# No loopback of transmitted frames

	set_bank(ECON1)													# Switch to bank 0
	write_op(ENC28J60_BIT_FIELD_SET, EIE, EIE_INTIE | EIE_PKTIE)	# Enable interrutps
	write_op(ENC28J60_BIT_FIELD_SET, ECON1, ECON1_RXEN)				# Enable packet reception

	log("ENC28J60 Revision {:d}".format(read_byte(EREVID)))
	link_status = is_link_up()
	packet_number = 0

	while packet_number < 1000000:
		new_status = is_link_up()

		if link_status != new_status:
			link_status = new_status
			log("link status = {}".format(link_status))

		packet = receive_packet()

		if len(packet) == 0:
			continue
		elif len(packet) >= 14:
			frame = EthernetFrame.from_buffer(packet)

			# if frame.type in (0x0800, 0x0806):
			if frame.type == 0x0806:
				packet_number += 1
				log()
				log("#{:d}\n{}".format(packet_number, frame))

				if frame.type == 0x0800:	# IPv4
					if frame.payload.protocol == 1:
						if frame.payload.payload.type == 8:
							log("ICMP Request")
				if frame.type == 0x0806:	# ARP
					if frame.payload.tpa == ip_addr:
						new_packet = packet[6:12]
						new_packet.extend(mac_addr)
						new_packet.extend(packet[12:14])
						new_packet.extend(frame.payload.response(mac_addr))
						send_packet(new_packet)
		else:
			log("possibly invalid packet: " + " ".join(["{:02x}".format(byte) for byte in packet]))

	log("done")
