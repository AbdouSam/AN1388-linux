#!/usr/bin/env python
"""Implementation of Microchip's AN1388 on Linux using UDP"""

from __future__ import print_function

import sys

import socket
from argparse import ArgumentParser, RawTextHelpFormatter
from binascii import hexlify, unhexlify

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

CRC_TABLE = [
    0x0000, 0x1021, 0x2042, 0x3063, 0x4084, 0x50a5, 0x60c6, 0x70e7,
    0x8108, 0x9129, 0xa14a, 0xb16b, 0xc18c, 0xd1ad, 0xe1ce, 0xf1ef]

DEBUG_LEVEL = 0
server_address = ('192.168.1.61', 6234) # default address and port

def crc16(data):
    """Calculate the CRC-16 for a string"""
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
        '-a', '--addr',
        help='Address IP to use',
        required=True)
    pars.add_argument(
        '-p', '--port',
        help='UDP port ',
        type=int, default=6234)
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

def send_request(soc, command):
    """Send a command over a UDP S"""
    global server_address

    command = escape(command)

    # Build and send request
    request = '\x01' + command + escape(crc16(command)) + '\x04'
    sent = soc.sendto(request, server_address)

    if DEBUG_LEVEL >= 2:
        print('>', hexlify(request))
    return len(request)

def read_response(soc, command):
    """Read the response from the UDP socket"""
    response = ''
    while len(response) < 4 \
          or response[-1] != '\x04' or response[-2] == '\x10':

        try:
            response, server = soc.recvfrom(1024)
        except Exception as e:
            print("Read Timed Out, Check IP addr, or port num")
            quit()

        if len(response) == 0:
            raise IOError('Bootloader response timed out')

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

def upload(soc, filename):
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
            txsize += send_request(soc, '\x03' + data)
            response = read_response(soc, '\x03')
            rxsize += len(response) + 4
            txcount += 1
            rxcount += 1
        print('*')
    return (txcount, txsize, rxcount, rxsize)

def main():
    """Main programmer function"""
    
    global DEBUG_LEVEL # pylint: disable=global-statement
    global server_address

    args = parse_args()

    DEBUG_LEVEL = args.debug

    addr_ip = str(args.addr)

    # Check valid Ip Address
    try:
        socket.inet_aton(addr_ip)
    except Exception as e:
        print("Err.Not a valid IP address")
        quit()

    udp_port = args.port

    # check if port is int
    try:
        udp_port = int(udp_port)
    except Exception as e:
        print("Err. UDP Port must be an integer")
        quit()

    read_timeout = args.timeout

    server_address = (addr_ip , udp_port)

    # Create a UDP socket
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    #Set socket Read timeout 
    soc.settimeout(read_timeout)

    print("Connecting to " + addr_ip + " : " + str(udp_port))

    if args.version:
        print('Querying..')
        send_request(soc, '\x01')
        version = read_response(soc, '\x01')
        print('Bootloader version: ' + hexlify(version))

    if args.erase:
        print('Erasing..')
        send_request(soc, '\x02')
        read_response(soc, '\x02')

    if args.upload != None:
        print('Uploading..')
        upstats = upload(soc, args.upload)
        print(
            'Transmitted: %d packets (%d bytes), '\
            'Received: %d packets (%d bytes)' % upstats)

    if args.check != None:
        print('Verifying..')
        addr, size = args.check.split(':')
        addr, size = addr.zfill(8), size.zfill(8)
        send_request(
            soc, '\x04' + unhexlify(addr)[::-1] + unhexlify(size)[::-1])
        checksum = read_response(soc, '\04')
        print('CRC @%s[%s]: %s' % (addr, size, hexlify(checksum)))

    if args.run:
        print('Running application..')
        send_request(soc, '\x05')

    print('Done.')

if __name__ == '__main__':
    main()