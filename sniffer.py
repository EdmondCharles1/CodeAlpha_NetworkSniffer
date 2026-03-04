import socket 
import struct
import textwrap


# Unpack Ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

# Return formatted MAC address (like AA:BB:CC:DD:EE:FF)
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

# Unpack IPv4 packet
def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

# Return formatted IPv4 address (like 192.168.1.1)
def ipv4(addr):
    return '.'.join(map(str, addr))

def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('  Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # 8 = IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print('  IPv4 Packet:')
            print('    Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('    Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

main()