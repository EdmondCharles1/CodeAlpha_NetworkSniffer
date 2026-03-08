from flask import Flask, jsonify, render_template_string
import socket
import struct
import threading

app = Flask(__name__)

# ============================================================
# Données partagées entre le sniffer et le dashboard
# ============================================================
# Le sniffer écrit dedans, le dashboard lit dedans
captured_packets = []
stats = {'total': 0, 'tcp': 0, 'udp': 0, 'icmp': 0, 'other': 0}

# ============================================================
# Fonctions de parsing (copiées depuis sniffer.py)
# ============================================================

def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()

def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, proto, ipv4(src), ipv4(target), data[header_length:]

def ipv4(addr):
    return '.'.join(map(str, addr))

def tcp_segment(data):
    src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    return src_port, dest_port, data[offset:]

def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]

def icmp_packet(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return icmp_type, code, checksum, data[4:]

# ============================================================
# Thread du sniffer — tourne en arrière-plan
# ============================================================
# Un thread c'est un processus parallèle
# Le sniffer capture les paquets pendant que Flask sert les pages
# daemon=True signifie que le thread s'arrête quand le programme principal s'arrête

def sniffer_thread():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    while True:
        raw_data, addr = conn.recvfrom(65536)
        dest_mac, src_mac, eth_proto, data = ethernet_frame(raw_data)

        if eth_proto == 8:
            version, header_length, ttl, proto, src, target, data = ipv4_packet(data)

            packet_info = {
                'src_mac': src_mac,
                'dest_mac': dest_mac,
                'src_ip': src,
                'dest_ip': target,
                'ttl': ttl,
                'protocol': '',
                'src_port': '',
                'dest_port': '',
            }

            if proto == 6:
                src_port, dest_port, data = tcp_segment(data)
                packet_info['protocol'] = 'TCP'
                packet_info['src_port'] = src_port
                packet_info['dest_port'] = dest_port
                stats['tcp'] += 1

            elif proto == 17:
                src_port, dest_port, size, data = udp_segment(data)
                packet_info['protocol'] = 'UDP'
                packet_info['src_port'] = src_port
                packet_info['dest_port'] = dest_port
                stats['udp'] += 1

            elif proto == 1:
                icmp_type, code, checksum, data = icmp_packet(data)
                packet_info['protocol'] = 'ICMP'
                stats['icmp'] += 1

            else:
                packet_info['protocol'] = 'OTHER'
                stats['other'] += 1

            stats['total'] += 1

            # Garder les 500 derniers paquets pour ne pas saturer la mémoire
            captured_packets.append(packet_info)
            if len(captured_packets) > 500:
                captured_packets.pop(0)

# ============================================================
# Routes API — le dashboard demande ces URLs pour avoir les données
# ============================================================

# Route API : renvoie les stats en JSON
# Le navigateur appelle cette URL pour mettre à jour les compteurs
@app.route('/api/stats')
def api_stats():
    return jsonify(stats)

# Route API : renvoie les paquets en JSON
# ?protocol=TCP filtre par protocole
@app.route('/api/packets')
def api_packets():
    from flask import request
    proto_filter = request.args.get('protocol', '').upper()
    if proto_filter and proto_filter != 'ALL':
        filtered = [p for p in captured_packets if p['protocol'] == proto_filter]
    else:
        filtered = captured_packets
    # Renvoyer les 100 derniers
    return jsonify(filtered[-100:])

# Route principale : affiche le dashboard HTML
@app.route('/')
def index():
    return render_template_string(open('templates/index.html').read())

# ============================================================
# Lancement
# ============================================================
if __name__ == '__main__':
    # Lancer le sniffer dans un thread séparé
    t = threading.Thread(target=sniffer_thread, daemon=True)
    t.start()
    print('Sniffer started in background...')
    print('Dashboard: http://127.0.0.1:5000')
    app.run(host='0.0.0.0', port=5000, debug=False)