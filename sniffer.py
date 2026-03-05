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



# ============================================================
# TCP Segment (Protocol 6)
# ============================================================
# Structure du header TCP (20 bytes minimum) :
# 
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |          Source Port          |       Destination Port        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                        Sequence Number                       |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |                    Acknowledgment Number                     |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |  Data |           |U|A|P|R|S|F|                              |
#  | Offset|  Reserved |R|C|S|S|Y|I|            Window            |
#  |       |           |G|K|H|T|N|N|                              |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Format struct : '! H H L L H'
#   ! = network byte order (big-endian)
#   H = unsigned short (2 bytes) → Source Port
#   H = unsigned short (2 bytes) → Destination Port
#   L = unsigned long  (4 bytes) → Sequence Number
#   L = unsigned long  (4 bytes) → Acknowledgment Number
#   H = unsigned short (2 bytes) → Data Offset + Reserved + Flags
#   Total = 14 bytes (on lit les 14 premiers bytes du segment TCP)

def tcp_segment(data):
    # Unpack les 14 premiers bytes du header TCP
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])

    # Data Offset = les 4 premiers bits (>> 12 pour les isoler)
    # Multiplié par 4 car exprimé en mots de 32 bits (4 bytes)
    # Exemple : offset = 5 → header TCP = 5 * 4 = 20 bytes
    offset = (offset_reserved_flags >> 12) * 4

    # Les 6 flags TCP sont dans les 6 derniers bits
    # Chaque flag = 1 bit (1 = actif, 0 = inactif)
    # On utilise un masque AND (&) pour isoler chaque bit
    #
    # Bit 5 (valeur 32) = URG (données urgentes)
    # Bit 4 (valeur 16) = ACK (accusé de réception)
    # Bit 3 (valeur 8)  = PSH (push, envoyer immédiatement)
    # Bit 2 (valeur 4)  = RST (reset, fermer la connexion)
    # Bit 1 (valeur 2)  = SYN (synchronize, ouvrir la connexion)
    # Bit 0 (valeur 1)  = FIN (finish, terminer la connexion)
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    # data[offset:] = le payload (données après le header TCP)
    return src_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]


# ============================================================
# UDP Segment (Protocol 17)
# ============================================================
# Structure du header UDP (8 bytes, beaucoup plus simple que TCP) :
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |          Source Port          |       Destination Port        |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |            Length             |           Checksum            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Format struct : '! H H 2x H'
#   H  = unsigned short (2 bytes) → Source Port
#   H  = unsigned short (2 bytes) → Destination Port
#   2x = on saute 2 bytes          → Length (on ne le lit pas ici)
#   H  = unsigned short (2 bytes) → Checksum
#
# Note : UDP n'a pas de flags, pas de sequence, pas d'acknowledgment
# C'est un protocole "fire and forget" — rapide mais sans garantie

def udp_segment(data):
    # Unpack les 8 premiers bytes du header UDP
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])

    # data[8:] = le payload (données après le header UDP de 8 bytes)
    return src_port, dest_port, size, data[8:]


# ============================================================
# ICMP Packet (Protocol 1)
# ============================================================
# Structure du header ICMP (4 bytes minimum) :
#
#   0                   1                   2                   3
#   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#  |     Type      |     Code      |          Checksum            |
#  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#
# Format struct : '! B B H'
#   B = unsigned char  (1 byte) → Type
#   B = unsigned char  (1 byte) → Code
#   H = unsigned short (2 bytes) → Checksum
#
# Types ICMP courants :
#   Type 0  = Echo Reply (réponse au ping)
#   Type 3  = Destination Unreachable (destination injoignable)
#   Type 8  = Echo Request (ping)
#   Type 11 = Time Exceeded (TTL expiré)
#
# Note : ICMP n'utilise PAS de ports, contrairement à TCP et UDP
# Il sert à envoyer des messages de contrôle (ping, erreurs réseau)

def icmp_packet(data):
    # Unpack les 4 premiers bytes du header ICMP
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])

    # data[4:] = le reste du paquet ICMP (données additionnelles)
    return icmp_type, code, checksum, data[4:]
def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)
        print('\nEthernet Frame:')
        print('  Destination: {}, Source: {}, Protocol: {}'.format(dest_mac, src_mac, eth_proto))

        # IPv4
        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)
            print('  IPv4 Packet:')
            print('    Version: {}, Header Length: {}, TTL: {}'.format(version, header_length, ttl))
            print('    Protocol: {}, Source: {}, Target: {}'.format(proto, src, target))

            # TCP
            if proto == 6:
                src_port, dest_port, sequence, ack, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = tcp_segment(data)
                print('    TCP Segment:')
                print('      Source Port: {}, Destination Port: {}'.format(src_port, dest_port))
                print('      Sequence: {}, Acknowledgment: {}'.format(sequence, ack))
                print('      Flags: URG={}, ACK={}, PSH={}, RST={}, SYN={}, FIN={}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))

            # UDP
            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                print('    UDP Segment:')
                print('      Source Port: {}, Destination Port: {}, Length: {}'.format(src_port, dest_port, size))

            # ICMP
            elif proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                print('    ICMP Packet:')
                print('      Type: {}, Code: {}, Checksum: {}'.format(icmp_type, code, checksum))

if __name__ == '__main__':
    main()