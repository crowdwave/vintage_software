# this is a nasty hack of the Python xmodem library
# it receives files from the sterm program for the Exidy Sorcerer Z80 antique computer
# it ONLY receives files from sterm's multiple file transfer function
# sterm seems to send something like xmodem but not quite, thus this hack
# hacked by Andrew Stuart andrew.stuart@supercoders.com.au Jan 2019

from __future__ import division, print_function

__author__ = 'Wijnand Modderman <maze@pyth0n.org>'
__copyright__ = ['Copyright (c) 2010 Wijnand Modderman',
                 'Copyright (c) 1981 Chuck Forsberg']
__license__ = 'MIT'
__version__ = '0.4.5'

import platform
import logging
import sys
from functools import partial
import time
import serial



# Protocol bytes
SOH_byte = b'\x01'
STX_byte = b'\x02'
ETX_byte = b'\x03'
EOT_byte = b'\x04'
ENQ_byte = b'\x05'
ACK_byte = b'\x06'
DLE_byte = b'\x10'
NAK_byte = b'\x15'
CAN_byte = b'\x18'
Z_byte = b'Z'

# Protocol bytes as hex
SOH_hex = '01'
STX_hex = '02'
ETX_hex = '03'
EOT_hex = '04'
ENQ_hex = '05'
ACK_hex = '06'
DLE_hex = '10'
NAK_hex = '15'
CAN_hex = '18'
Z_hex = '5a'

# Protocol bytes as decimal
SOH_decimal = 1
STX_decimal = 2
ETX_decimal = 3
EOT_decimal = 4
ENQ_decimal = 5
ACK_decimal = 6
NAK_decimal = 15
CAN_decimal = 18
CONTROL_Z_decimal = 26



class XMODEMSTERM(object):
    '''
    XMODEMSTERM Protocol handler, expects two callables which encapsulate the read
        and write operations on the underlying stream.

    Example functions for reading and writing to a serial line:

    >>> import serial
    >>> from xmodem import XMODEMSTERM
    >>> ser = serial.Serial('/dev/ttyUSB0', timeout=0) # or whatever you need
    >>> def getc(size, timeout=1):
    ...     return ser.read(size) or None
    ...
    >>> def putc(data, timeout=1):
    ...     return ser.write(data) or None
    ...
    >>> modem = XMODEMSTERM(getc, putc)


    :param getc: Function to retrieve bytes from a stream. The function takes
        the number of bytes to read from the stream and a timeout in seconds as
        parameters. It must return the bytes which were read, or ``None`` if a
        timeout occured.
    :type getc: callable
    :param putc: Function to transmit bytes to a stream. The function takes the
        bytes to be written and a timeout in seconds as parameters. It must
        return the number of bytes written to the stream, or ``None`` in case of
        a timeout.
    :type putc: callable
    :param mode: XMODEMSTERM protocol mode
    :type mode: string
    :param pad: Padding character to make the packets match the packet size
    :type pad: char

    '''

    # crctab calculated by Mark G. Mendel, Network Systems Corporation
    crctable = [
        0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
        0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef,
        0x1231, 0x0210, 0x3273, 0x2252, 0x52b5, 0x4294, 0x72f7, 0x62d6,
        0x9339, 0x8318, 0xb37b, 0xa35a, 0xd3bd, 0xc39c, 0xf3ff, 0xe3de,
        0x2462, 0x3443, 0x0420, 0x1401, 0x64e6, 0x74c7, 0x44a4, 0x5485,
        0xa56a, 0xb54b, 0x8528, 0x9509, 0xe5ee, 0xf5cf, 0xc5ac, 0xd58d,
        0x3653, 0x2672, 0x1611, 0x0630, 0x76d7, 0x66f6, 0x5695, 0x46b4,
        0xb75b, 0xa77a, 0x9719, 0x8738, 0xf7df, 0xe7fe, 0xd79d, 0xc7bc,
        0x48c4, 0x58e5, 0x6886, 0x78a7, 0x0840, 0x1861, 0x2802, 0x3823,
        0xc9cc, 0xd9ed, 0xe98e, 0xf9af, 0x8948, 0x9969, 0xa90a, 0xb92b,
        0x5af5, 0x4ad4, 0x7ab7, 0x6a96, 0x1a71, 0x0a50, 0x3a33, 0x2a12,
        0xdbfd, 0xcbdc, 0xfbbf, 0xeb9e, 0x9b79, 0x8b58, 0xbb3b, 0xab1a,
        0x6ca6, 0x7c87, 0x4ce4, 0x5cc5, 0x2c22, 0x3c03, 0x0c60, 0x1c41,
        0xedae, 0xfd8f, 0xcdec, 0xddcd, 0xad2a, 0xbd0b, 0x8d68, 0x9d49,
        0x7e97, 0x6eb6, 0x5ed5, 0x4ef4, 0x3e13, 0x2e32, 0x1e51, 0x0e70,
        0xff9f, 0xefbe, 0xdfdd, 0xcffc, 0xbf1b, 0xaf3a, 0x9f59, 0x8f78,
        0x9188, 0x81a9, 0xb1ca, 0xa1eb, 0xd10c, 0xc12d, 0xf14e, 0xe16f,
        0x1080, 0x00a1, 0x30c2, 0x20e3, 0x5004, 0x4025, 0x7046, 0x6067,
        0x83b9, 0x9398, 0xa3fb, 0xb3da, 0xc33d, 0xd31c, 0xe37f, 0xf35e,
        0x02b1, 0x1290, 0x22f3, 0x32d2, 0x4235, 0x5214, 0x6277, 0x7256,
        0xb5ea, 0xa5cb, 0x95a8, 0x8589, 0xf56e, 0xe54f, 0xd52c, 0xc50d,
        0x34e2, 0x24c3, 0x14a0, 0x0481, 0x7466, 0x6447, 0x5424, 0x4405,
        0xa7db, 0xb7fa, 0x8799, 0x97b8, 0xe75f, 0xf77e, 0xc71d, 0xd73c,
        0x26d3, 0x36f2, 0x0691, 0x16b0, 0x6657, 0x7676, 0x4615, 0x5634,
        0xd94c, 0xc96d, 0xf90e, 0xe92f, 0x99c8, 0x89e9, 0xb98a, 0xa9ab,
        0x5844, 0x4865, 0x7806, 0x6827, 0x18c0, 0x08e1, 0x3882, 0x28a3,
        0xcb7d, 0xdb5c, 0xeb3f, 0xfb1e, 0x8bf9, 0x9bd8, 0xabbb, 0xbb9a,
        0x4a75, 0x5a54, 0x6a37, 0x7a16, 0x0af1, 0x1ad0, 0x2ab3, 0x3a92,
        0xfd2e, 0xed0f, 0xdd6c, 0xcd4d, 0xbdaa, 0xad8b, 0x9de8, 0x8dc9,
        0x7c26, 0x6c07, 0x5c64, 0x4c45, 0x3ca2, 0x2c83, 0x1ce0, 0x0cc1,
        0xef1f, 0xff3e, 0xcf5d, 0xdf7c, 0xaf9b, 0xbfba, 0x8fd9, 0x9ff8,
        0x6e17, 0x7e36, 0x4e55, 0x5e74, 0x2e93, 0x3eb2, 0x0ed1, 0x1ef0,
    ]

    def __init__(self, getc, putc, verbose=False, port='com2', baudrate='1200', pad=b'\x1a'):
        self.getc = getc
        self.putc = putc
        self.stream = None
        self.port = port
        self.baudrate = baudrate
        self.verbose = verbose
        self.pad = pad
        self.log = logging.getLogger('xmodem.XMODEMSTERM')

    def abort(self, count=2, timeout=60):
        '''
        Send an abort sequence using CAN bytes.

        :param count: how many abort characters to send
        :type count: int
        :param timeout: timeout in seconds
        :type timeout: int
        '''
        for _ in range(count):
            self.putc(CAN, timeout)
        sys.exit(1)


    def process_first_packet(self, packet_received_data_bytes):
        # DEBUG print('this should be packet_number number 1 containing the filename')
        # the first packet from sterm contains the filename
        filename = packet_received_data_bytes.decode("utf-8") 
        print('filename', filename)
        if filename == '@@@@@@@@@@@':
            # sterm seems to send this as the filename to indicate no more files to receive
            print('All files received, exiting.')
            # DEBUG print('sending ACK')
            self.putc(ACK_byte)
            sys.exit(0)

        # replace illegal characters in filenames
        filename = filename.replace('/','_')
        filename = filename.replace('\\','_')
        prefix = filename[0:8] # CP/M filenames are 8 characters
        prefix = prefix.strip()
        suffix = filename[-3:] # plus 3 character suffix
        suffix = suffix.strip()
        if suffix:
            filename = prefix + '.' + suffix
        else:
            filename = prefix
        self.create_output_file(filename)

    def create_output_file(self, filename):
        # create a stream at this point with the filename
        print('Creating file: ', filename)
        self.stream = open(filename, 'wb')

    def decode_sterm_data_byte_pair(self, data_byte):
        # sterm encodes protocol bytes as two byte values.  we need to look for them and convert them.
        print('decode_sterm_data_byte_pair got ', data_byte)
        encoded_bytes = {
            b'A': bytes([1]),
            b'B': bytes([2]),
            b'C': bytes([3]),
            b'D': bytes([4]),
            b'E': bytes([5]),
            b'F': bytes([6]),
            b'U': bytes([21]),
            b'Z': bytes([26]),
            b'\xc0': b'\x80',
        }
        if data_byte not in encoded_bytes.keys():
            # this is not an encoded byte pair
            return None
        print('encoded_bytes[data_byte] ', encoded_bytes[data_byte])
        return encoded_bytes[data_byte]

    def recv(self, crc_mode=0, retry=16, timeout=60, delay=1, quiet=0):

        error_count = 0
        income_size = 0
        packet_size = 128
        packet_number = 0
        cancel = 0
        # send an ACK
        self.putc(ACK_byte)
        # get next byte from serial port
        char = self.getc(1, timeout)
        while True:
            packet_number += 1
            print('packet_number: ', packet_number)
            while True:
                #############################################
                # start loop while receiving packet header bytes 
                #############################################
                print('processing a new packet header')
                print('char', char)

                if char == SOH_byte:
                    self.log.debug('recv: SOH')
                    break
                elif char == STX_byte:
                    self.log.debug('recv: STX')
                    break
                elif char == EOT_byte:
                    # We received an EOT, so send an ACK and return the
                    # received data length.
                    self.putc(ACK_byte)
                    self.log.info("Transmission complete, %d bytes",
                                  income_size)
                    print("Transmission complete, %d bytes", income_size)

                    return income_size
                elif char == CAN_byte:
                    # cancel at two consecutive cancels
                    if cancel:
                        self.log.info('Transmission canceled: received 2xCAN '
                                      'at packet_number %d', packet_number)
                        return None
                    else:
                        self.log.debug('cancellation at packet_number %d', packet_number)
                        cancel = 1
                else:
                    err_msg = ('recv error: expected SOH, EOT; '
                               'got {0!r}, acking and naking'.format(char))
                    if not quiet:
                        print(err_msg, file=sys.stderr)
                    self.log.warn(err_msg)
                    error_count += 1
                    print( bytes([10]))
                    #input("Press Enter to send ")
                    self.putc( bytes([6]))
                    break

                    if error_count > retry:
                        self.log.info('error_count reached %d, aborting.',
                                      retry)
                        self.abort()
                        return None
                #############################################
                # finished loop while receiving packet header bytes 
                #############################################

            error_count = 0
            cancel = 0
            self.log.debug('recv: packet_number %d', packet_number)
            # packet_size + checksum
            self.putc(ACK_byte)
            
            etxfound = False
            # DEBUG print('reading packet data')
            previous_byte_was_ascii128 = False
            self.verbose = True

            # sterm's  packet structure:
            # 1 byte ASCII STX 
            # 11 data bytes for the first packet (the filename packet)
            # 128 bytes for all packets after the first
            # 1 byte ASCII ETX 
            # 1 byte checksum
            # 1 byte ASCII ENQ 

            # read packet bytes from serial port
            num_footer_bytes_per_packet = 3
            number_data_bytes_received = 0
            if packet_number == 1: # packet 1 is the filename packet
                num_data_bytes_per_packet = 11
                packet_received_data_bytes = self.getc(num_data_bytes_per_packet + num_footer_bytes_per_packet)
                number_data_bytes_received += len(packet_received_data_bytes)
                self.process_first_packet(packet_received_data_bytes[0:num_data_bytes_per_packet])
                # send an ACK
                self.putc(ACK_byte)
                # get next byte from serial port
                char = self.getc(1, timeout)
                continue
            else: # all packets after 1 are data packets
                num_data_bytes_per_packet = 128
                number_of_two_byte_pads_found = 0
                #previous_byte_was_ascii128 = False
                packet_data = bytearray()
                encoded_byte_start_found = False
                while True:
                    # IMPORTANT!!
                    # sterm seems to send 128 bytes of data
                    # UNLESS it includes two_byte_pad which is ASCII128 + ASCII90
                    # in which case, we just need to keep reading till the footer
                    received_data_byte = self.getc(1)
                    print('received_data_byte', received_data_byte, type(received_data_byte))
                    if received_data_byte == b'\x80':
                        if encoded_byte_start_found:
                            # THIS SHOULD NOT BE POSSIBLE - ANY BYTES IN DATA PACKET PREFIXED WITH \x80
                            # should be found in the encoding lookup.

                            # second of two b'\x80' in a row, 
                            # so put the \x80 back into the data 128 is decimal of \x80
                            packet_data.append(128)
                        # this is start of an encoded byte pair
                        encoded_byte_start_found = True
                        continue
                    if encoded_byte_start_found:
                        encoded_data_byte = self.decode_sterm_data_byte_pair(received_data_byte)
                        if not encoded_data_byte:
                            # THIS SHOULD NOT BE POSSIBLE - ANY BYTES IN DATA PACKET PREFIXED WITH \x80
                            # should be found in the encoding lookup.

                            # this is not an encoded byte pair, 
                            # so put the \x80 back into the data 128 is decimal of \x80
                            packet_data.append(128)
                        else:
                            received_data_byte = encoded_data_byte
                    encoded_byte_start_found = False
                    print(received_data_byte)
                    print(received_data_byte[0])

                    packet_data.append(received_data_byte[0])
                    print('packet_data', packet_data)
                    number_data_bytes_received += 1

                    if len(packet_data) >= 2: 
                        if packet_data[-2] == 128 and packet_data[-1] == CONTROL_Z_decimal: 
                            # the two bytes just read appear to be a 2 byte pad
                            if self.verbose:
                                print('found two byte pad')
                            number_of_two_byte_pads_found += 1

                    
                    # this must be a data packet that contains 2 byte pad
                    # so we must continue reading bytes until the footer is found

                    if len(packet_data) == (num_data_bytes_per_packet + num_footer_bytes_per_packet):
                        # once we have 128 VALID data bytes i.e. decoded byte pair is 1 byte not 2
                        # then we should have a valid 3 byte footer
                        if packet_data[-1] == ENQ_decimal and packet_data[-3] == ETX_decimal: 
                            # packet footer is 3 bytes - 1 byte ENQ 1 byte checksum and 1 byte ETX
                            # so we have to keep reading until the packet footer is found
                            break

                packet_received_data_bytes = bytes(packet_data)

            if self.verbose:
                print('number of data bytes in packet: ', number_data_bytes_received)

            packet_received_ETX = packet_received_data_bytes[-3]
            packet_received_CHECKSUM = packet_received_data_bytes[-2]
            packet_received_ENQ = packet_received_data_bytes[-1]
            if self.verbose == True:
                print('packet_received_data_bytes: ')
                print(packet_received_data_bytes)
                print('packet_received_ETX: ', packet_received_ETX)
                print('packet_received_CHECKSUM: ', packet_received_CHECKSUM)
                print('packet_received_ENQ: ', packet_received_ENQ)
            print(ETX_byte)
            print(packet_received_ETX)

            if packet_received_ETX != ETX_decimal:
                print('error, did not get expected ETX')
                sys.exit(1)

            if packet_received_ENQ != ENQ_decimal:
                print('error, did not get expected ENQ')
                sys.exit(1)

            #valid = self._verify_recv_checksum(packet_received_data_bytes, packet_received_CHECKSUM)
            checksum_valid = True

            if checksum_valid != True:
                print('error, checksum not valid')
                sys.exit(1)


            data_portion_of_packet = packet_received_data_bytes[:-3] # chop off the 3 packet footer bytes
            print('packet_number ', packet_number)
            # send an ACK
            self.putc(ACK_byte)
            # get next byte from serial port
            char = self.getc(1, timeout)
            if char == EOT_byte:
                # this is the end of the file transmission, so strip control Z's from last packet
                final_packet_data = bytearray(data_portion_of_packet)
                if len(final_packet_data) >= 2:
                    while final_packet_data[-1] == CONTROL_Z_decimal and  final_packet_data[-2] == CONTROL_Z_decimal: 
                        # we ensure that downloaded files end with a maximum of one control Z
                        # thus we test to see if the packet data ends with two control z's 
                        # if so, remove one of them and let the evaluation loop run again

                        #
                        if self.verbose:
                            print('final_packet before stripping a control Z from end: ', final_packet_data) 
                        final_packet_data = final_packet_data[:-1]
                        if self.verbose:
                            print('final_packet after stripping a control Z from end: ', final_packet_data) 
                data_portion_of_packet = bytes(final_packet_data)
            income_size += len(packet_received_data_bytes)
            self.stream.write(data_portion_of_packet)
            print('.', end="")

            continue


    def _verify_recv_checksum(self,  data, checksum):
        our_sum = self.calc_checksum(data, checksum)
        valid = checksum == our_sum
        if not valid:
            self.log.warn('recv error: checksum fail '
                            '(theirs=%02x, ours=%02x)',
                            checksum, our_sum)
        return valid

    def calc_checksum(self, data, checksum):
        '''
        Calculate the checksum for a given block of data, can also be used to
        update a checksum.

            >>> csum = modem.calc_checksum('hello')
            >>> csum = modem.calc_checksum('world', csum)
            >>> hex(csum)
            '0x3c'

        '''
        if platform.python_version_tuple() >= ('3', '0', '0'):
            return (sum(data) + checksum) % 256
        else:
            return (sum(map(ord, data)) + checksum) % 256

    def calc_crc(self, data, crc=0):
        '''
        Calculate the Cyclic Redundancy Check for a given block of data, can
        also be used to update a CRC.

            >>> crc = modem.calc_crc('hello')
            >>> crc = modem.calc_crc('world', crc)
            >>> hex(crc)
            '0xd5e3'

        '''
        for char in bytearray(data):
            crctbl_idx = ((crc >> 8) ^ char) & 0xff
            crc = ((crc << 8) ^ self.crctable[crctbl_idx]) & 0xffff
        return crc & 0xffff




def run():
    import optparse

    parser = optparse.OptionParser(
        usage='%prog [<options>]')
    parser.add_option(
        '-v', 
        '--verbose', 
        default=False, 
        help='stermrecv -v', 
        dest='verbose', 
        action='store_true',
        )

    parser.add_option(
        '-b', 
        '--baudrate', 
        default='1200', 
        help='stermrecv -v', 
        dest='baudrate', 
        )

    parser.add_option(
        '-p', 
        '--p', 
        default='com2', 
        help='stermrecv -v', 
        dest='port', 
        )

    options, args = parser.parse_args()

    # configure the serial connections (the parameters differs on the device you are connecting to)
    ser = serial.Serial(
        port='com2',
        baudrate=1200,
        parity=serial.PARITY_EVEN,
        stopbits=serial.STOPBITS_ONE,
        bytesize=serial.EIGHTBITS
    )

    verbose = True

    def getc(size, timeout=1):
        got = ser.read(size) or None
        if verbose == True:
            print('getc: got, got.hex()', got, got.hex())
        return got

    def putc(data, timeout=1):
        if verbose == True:
            print('putc: data, ord(data), data.hex()', data, ord(data), data.hex())
        return ser.write(data)  # note that this ignores the timeout

    #logging.basicConfig(level=logging.DEBUG)


    print(
        'Starting sterm client receive.\n'
        'WARNING! THIS OVERWRITES EXISTING FILES WITHOUT ASKING!!!!!!!\n'
        'IMPORTANT! You MUST start this BEFORE commencing "Multiple file transfer" from sterm\n'
        'On Windows - hit ctrl-break to exit\n'
        'On Linux - hit ctrl-C to exit\n'
    )

    while True:
        print('Waiting for file')
        xmodem = XMODEMSTERM(getc, putc, verbose=options.verbose, port=options.port, baudrate=options.baudrate)
        xmodem.recv()
        print('File receive ended')


if __name__ == '__main__':
    sys.exit(run())
