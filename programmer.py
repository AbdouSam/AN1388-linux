#!/usr/bin/env python
"""Implementation of Microchip's AN1388 on Linux using UART"""

# TODO :
# - send_request and read_response are almost the same in both
#   Classes, we can optimize the code, making a common send and read
# -
#


from __future__ import print_function

import sys

import socket
import serial

from argparse import ArgumentParser, RawTextHelpFormatter
from binascii import hexlify, unhexlify
import abc
from abc import ABCMeta, abstractmethod 

__author__ = "Camil Staps, V Govorovski"
__copyright__ = "Copyright 2015, Camil Staps"
__credits__ = [
    "Camil Staps",
    "Ganapathi Ramachandra (Microchip Technology Inc.)",
    "Vadim Govorovski (Interface Devices Ltd.)"]
__license__ = "GPL"
__version__ = "0.3"
__maintainer__ = "Camil Staps"
__email__ = "info@camilstaps.nl"
__status__ = "Development"

# Tables are excatly the same, except the [-2] element, it depend on 
# the version of bootloader Library you are using on your PIC MCU

CRC_TABLE_0 = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1c1, 0xf1ef]

CRC_TABLE_1 = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef]

DEBUG_LEVEL = 0

class DataStream:
    __metaclass__ = ABCMeta

    global DEBUG_LEVEL

    def process_read_response(self,response, command):
        
        if DEBUG_LEVEL >= 2:
            print('<', hexlify(response))

        if response[0] != '\x01' or response[-1] != '\x04':
            raise IOError('Invalid response from bootloader')

        response = unescape(response[1:-1])

        # Verify SOH, EOT and command fields
        if response[0] != command:
            raise IOError('Unexpected response type from bootloader')
        if crc16(response[:-2]) != response[-2:]:
            raise IOError('Invalid CRC from bootloader')

        return response[1:-2]

    def process_send_request(self, request, command):
        
        if DEBUG_LEVEL >= 2:
            print('>', hexlify(request))

        return len(request)

    @abstractmethod
    def read_response(self, stream, command):
        pass

    @abstractmethod
    def send_request(self, stream, command):
        pass

class UDPStream(DataStream):

 
    def __init__(self, udp_addr, udp_port, timeout):
        self.udp_addr = udp_addr
        self.udp_port = udp_port
        self.timeout  = timeout
        self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.soc.settimeout(self.timeout)

    def udp_read(self, command):
        response = ''

        try:
            response, server = self.soc.recvfrom(1024)
        except Exception as e:
            print("Read Timed Out, Check IP addr, or port num")
            quit()

        return response

    def read_response(self, command):

        response = self.udp_read(command)

        return super(UDPStream, self).process_read_response(response, command)

    def udp_send(self, request):

        self.soc.sendto(request, (self.udp_addr , self.udp_port))

    def send_request(self, command):
        command = escape(command)

        # Build and send request
        request = '\x01' + command + escape(crc16(command)) + '\x04'
        
        self.udp_send(request)

        return super(UDPStream, self).process_send_request(request, command)

class UARTStream(DataStream):

    def __init__(self, uart_port, uart_baud, timeout):
        self.uart_port = uart_port
        self.uart_baud = uart_baud
        self.timeout   = timeout
        self.ser = serial.Serial(self.uart_port,
                                self.uart_baud,
                                timeout=self.timeout)

    def serial_read(self, command):
        response = ''
        
        while len(response) < 4 \
              or response[-1] != '\x04' or response[-2] == '\x10':

            byte = self.ser.read(1)

            if len(byte) == 0:
                raise IOError('Bootloader response timed out')
            if byte == '\x01' or len(response) > 0:
                response += byte

        return response

    def read_response(self, command):
        
        response = self.serial_read(command)

        return super(UARTStream, self).process_read_response(response, command)

    def serial_send(self, request):

        self.ser.write(request)

    def send_request(self, command):
        command = escape(command)

        # Build and send request
        request = '\x01' + command + escape(crc16(command)) + '\x04'

        self.serial_send(request)

        return super(UARTStream, self).process_send_request(request, command)


def crc16(data):
    """Calculate the CRC-16 for a string"""

    CRC_TABLE = CRC_TABLE_0

    i = 0
    crc = 0
    for byte in data:
        i = (crc >> 12) ^ (ord(byte) >> 4)
        crc = CRC_TABLE[i & 0x0f] ^ (crc << 4)
        i = (crc >> 12) ^ (ord(byte) >> 0)
        crc = CRC_TABLE[i & 0x0f] ^ (crc << 4)

    return chr(crc & 0xff) + chr((crc >> 8) & 0xff)

def parse_args():
    """Parse command line arguments"""
    pars = ArgumentParser(formatter_class=RawTextHelpFormatter)
    
    pars.add_argument(
        '-i', '--interface',
        help='Choose bootloader communication interface',
        choices=['uart','udp'],
        required=True)

    pars.add_argument(
        '-a','--udp-addr',
        help='IP Address for UDP')

    pars.add_argument(
        '-n','--udp-port',
        help='UDP port number',
        type=int, default=6234)
    
    pars.add_argument(
        '-p', '--port',
        help='Serial port to use')

    pars.add_argument(
        '-b', '--baud',
        help='Baudrate to the bootloader',
        type=int, default=115200)

    pars.add_argument(
        '-u', '--upload',
        help='Upload file to chip',
        metavar='firmware.hex')

    pars.add_argument(
        '-c', '--check',
        help='Check CRC of a memory block ADDR:SIZE\n'\
             '  ADDR - 32 bit start address (hex)\n'\
             '  SIZE - 32 bit block length in bytes',
        type=str, default='9d000000:000000ff',
        nargs='?')

    pars.add_argument(
        '-e', '--erase',
        help='Erase before upload',
        action='store_true')

    pars.add_argument(
        '-r', '--run',
        help='Run after upload',
        action='store_true')

    pars.add_argument(
        '-v', '--version',
        help='Read bootloader version',
        action='store_true')

    pars.add_argument(
        '-t', '--timeout',
        help='Timeout in seconds',
        type=float, default=1.0)

    pars.add_argument(
        '-D', '--debug',
        help='Debug level',
        type=int, default=0)

    pars.add_argument(
        '--my-version',
        action='version',
        version='%(prog)s ' + __version__)

    return pars.parse_args()

def escape(data):
    """Escape control characters"""
    data = data.replace('\x10', '\x10\x10')
    data = data.replace('\x01', '\x10\x01')
    data = data.replace('\x04', '\x10\x04')
    return data

def unescape(data):
    """Inverse of escape"""
    escaping = False
    record = ''
    for byte in list(data):
        if escaping:
            record += byte
            escaping = False
        elif byte == '\x10':
            escaping = True
        else:
            record += byte
    return record

def upload(conn_stream, filename):
    """Upload a hexfile"""
    txcount, rxcount, txsize, rxsize = 0, 0, 0, 0
    with open(filename) as hexfile:
        for line in hexfile:
            # Check Intel HEX format
            if len(line) < 7:
                raise IOError('Invalid record format')
            if DEBUG_LEVEL >= 1:
                print(line)
            else:
                sys.stdout.write('.')
                sys.stdout.flush()
            # Convert from ASCII to hexdec
            data = unhexlify(line[1:-1])
            txsize += conn_stream.send_request('\x03' + data)
            response = conn_stream.read_response('\x03')
            rxsize += len(response) + 4
            txcount += 1
            rxcount += 1
        print('*')
    return (txcount, txsize, rxcount, rxsize)

def main():
    """Main programmer function"""
    global DEBUG_LEVEL # pylint: disable=global-statement

    args = parse_args()

    DEBUG_LEVEL = args.debug
    
    if (args.interface == 'uart'):

        #Check required field
        if (args.port is None):
            raise IOError("-p or --port is required in UART interface")

        print("Connecting to port: " + str(args.port) + " at baude: " \
                                                      + str(args.baud))

        conn_stream = UARTStream(args.port, args.baud, args.timeout)

    elif (args.interface == 'udp'):

        #Check required field
        if (args.udp_addr is None):
            raise IOError("-a or --udp-addr is required in UDP interface")

        print("Connecting to address: " + str(args.udp_addr) \
                       + " at port: "  + str(args.udp_port))

        conn_stream = UDPStream(args.udp_addr, args.udp_port, args.timeout) 

    if args.version:
        print('Querying..')
        conn_stream.send_request('\x01')
        version = conn_stream.read_response('\x01')
        print('Bootloader version: ' + hexlify(version))

    if args.erase:
        print('Erasing..')
        conn_stream.send_request('\x02')
        conn_stream.read_response('\x02')

    if args.upload != None:
        print('Uploading..')
        upstats = upload(conn_stream, args.upload)
        print(
            'Transmitted: %d packets (%d bytes), '\
            'Received: %d packets (%d bytes)' % upstats)

    if args.check != None:
        print('Verifying..')
        addr, size = args.check.split(':')
        addr, size = addr.zfill(8), size.zfill(8)
        conn_stream.send_request(
            '\x04' + unhexlify(addr)[::-1] + unhexlify(size)[::-1])
        checksum = conn_stream.read_response('\04')
        print('CRC @%s[%s]: %s' % (addr, size, hexlify(checksum)))

    if args.run:
        print('Running application..')
        conn_stream.send_request('\x05')

    print('Done.')

if __name__ == '__main__':
    main()
