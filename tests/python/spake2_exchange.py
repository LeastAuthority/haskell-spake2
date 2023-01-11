#!/usr/bin/python
"""Exchange SPAKE2 keys and print out the session key.

Assumes symmetric exchange and uses the default SPAKE2 parameters.
"""
import argparse
from binascii import hexlify, unhexlify
import attr
import sys

from spake2 import SPAKE2_A, SPAKE2_B, SPAKE2_Symmetric


def main():
    parser = argparse.ArgumentParser(prog='version_exchange')
    parser.add_argument(
        '--code', dest='code', type=str,
        help='Password to use to connect to other side')
    parser.add_argument(
        '--side-id', dest='side_id', type=str,
        help='Identifier for this side of the exchange')
    parser.add_argument(
        '--side', dest='side', choices=['A', 'B', 'S'],
        help=('Which side this represents. '
              'Decides whether we use symmetric or asymmetric variant.'))
    parser.add_argument(
        '--other-side-id', dest='other_side_id', type=str,
        help=('Identifier for other side of the exchange. '
              'Only necessary for asymmetric variants.'))
    params = parser.parse_args(sys.argv[1:])
    transport = Transport(input_stream=sys.stdin, output_stream=sys.stdout)
    protocol = get_protocol(
        params.code, params.side, params.side_id, params.other_side_id)
    run_exchange(transport, protocol)


def get_protocol(code, side, side_id, other_side_id):
    code = code.encode('utf8')
    side_id = side_id.encode('utf8')
    if side == 'S':
        return SPAKE2_Symmetric(code, idSymmetric=side_id)
    other_side_id = other_side_id.encode('utf8')
    if side == 'A':
        return SPAKE2_A(code, idA=side_id, idB=other_side_id)
    elif side == 'B':
        return SPAKE2_B(code, idA=other_side_id, idB=side_id)
    else:
        raise AssertionError('Invalid side: %r' % (side,))


def run_exchange(transport, protocol):
    # Send the SPAKE2 message
    outbound = protocol.start()
    transport.send_line(hexlify(outbound))

    # Receive SPAKE2 message
    pake_msg = transport.receive_line()
    inbound = unhexlify(pake_msg)
    spake_key = protocol.finish(inbound)
    transport.send_line(hexlify(spake_key))


@attr.s
class Transport(object):
    input_stream = attr.ib()
    output_stream = attr.ib()

    def send_line(self, line):
        self.output_stream.write(line.rstrip().decode("utf8"))
        self.output_stream.write('\n')
        self.output_stream.flush()

    def receive_line(self):
        return self.input_stream.readline().strip()


if __name__ == '__main__':
    main()
