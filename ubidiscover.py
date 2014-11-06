import socket
import sys
import struct
import binascii
import json
import select

def parse_macaddr(bstr):
    raw = binascii.b2a_hex(bstr)
    return "%s:%s:%s:%s:%s:%s" % (raw[0:2], raw[2:4], raw[4:6], raw[6:8], raw[8:10], raw[10:12])

def parse_response(msg):
    magic, msg_type, msg_length = struct.unpack("!BBH", msg[0:4])
    msg_body = msg[4:]
    cur_pos = 0

    ret = { 'addresses' : [] }

    while cur_pos < msg_length:
        rest = msg_body[cur_pos:]
        tlv_type, tlv_length = struct.unpack("!BH", rest[0:3])
        tlv_value = rest[3:3+tlv_length]

        if   (tlv_type == 1):
            ret['hwaddr'] = parse_macaddr(tlv_value)
        elif (tlv_type == 2):
            ret['addresses'].append({
                'hwaddr' : parse_macaddr(tlv_value[0:6]),
                'ipv4'   : socket.inet_ntop(socket.AF_INET, tlv_value[6:])
            })
        elif (tlv_type == 3):
            ret['fwversion'] = tlv_value
        elif (tlv_type == 10):
            ret['uptime'] = struct.unpack("!L", tlv_value)[0]
        elif (tlv_type == 11):
            ret['hostname'] = tlv_value
        elif (tlv_type == 12):
            ret['product'] = tlv_value
        elif (tlv_type == 13):
            ret['essid'] = tlv_value
        elif (tlv_type == 14):
            ret['wmode'] = struct.unpack("B", tlv_value)[0]
        elif (tlv_type == 16):
            ret['product_code'] = struct.unpack("H", tlv_value)[0]
        else:
            print("unknown type %d. data: %s" % (tlv_type, binascii.b2a_hex(tlv_value)))

        cur_pos += tlv_length + 3

    return ret


if __name__ != "__main__":
    exit(1)

if len(sys.argv) < 2:
    print("usage: %s <hostname>" % sys.argv[0])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

try:
    sock.connect((sys.argv[1], 10001))
except Exception as e:
    print("error: %s" % e)
    exit(1)

sock.send(struct.pack("BBBB", 1, 0, 0, 0))

responses = []

while True:
    r,w,x = select.select([sock], [], [], 2)
    if not r:
        break
    data = sock.recv(4096)
    responses.append(parse_response(data))

print(json.dumps(responses))

