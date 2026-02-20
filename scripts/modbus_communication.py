#!/usr/bin/env python
from scapy.all import *
from Modbus.Modbus import *
import time
import random

# ============================================
# CONFIGURACIÓN - AJUSTAR SEGÚN TU ENTORNO
# ============================================
srcIP    = '192.168.1.64'  # IP de Kali (atacante)
srcPort  = random.randint(1024, 65535)
dstIP    = '192.168.1.66'  # IP de Ubuntu (servidor Modbus)
dstPort  = 5020
seqNr    = random.randint(444, 8765432)
ackNr    = 0
transID  = random.randint(44, 44444)

# ============================================
# FUNCIONES AUXILIARES
# ============================================

def updateSeqAndAckNrs(sendPkt, recvdPkt):
    """Actualiza números de secuencia y ACK de TCP"""
    global seqNr
    global ackNr
    seqNr = seqNr + len(sendPkt[TCP].payload)
    ackNr = ackNr + len(recvdPkt[TCP].payload)

def sendAck():
    """Envía paquete ACK"""
    ip = IP(src=srcIP, dst=dstIP)
    ACK = TCP(sport=srcPort, dport=dstPort, flags='A',
              seq=seqNr, ack=ackNr)
    pktACK = ip / ACK
    send(pktACK)

def tcpHandshake():
    """Establece conexión TCP (three-way handshake)"""
    global seqNr
    global ackNr

    # Crear paquete SYN
    ip = IP(src=srcIP, dst=dstIP)
    SYN = TCP(sport=srcPort, dport=dstPort, flags='S',
              seq=seqNr, ack=ackNr)
    pktSYN = ip / SYN

    # Enviar SYN y recibir SYN/ACK
    print("[*] Enviando SYN...")
    pktSYNACK = sr1(pktSYN)
    print("[+] Recibido SYN/ACK")

    # Crear y enviar ACK
    ackNr = pktSYNACK.seq + 1
    seqNr = seqNr + 1
    ACK = TCP(sport=srcPort, dport=dstPort, flags='A',
              seq=seqNr, ack=ackNr)
    send(ip / ACK)
    print("[+] Conexión TCP establecida")

    return ip/ACK

def endConnection():
    """Termina la conexión TCP"""
    ip = IP(src=srcIP, dst=dstIP)
    RST = TCP(sport=srcPort, dport=dstPort, flags='RA',
              seq=seqNr, ack=ackNr)
    pktRST = ip / RST
    send(pktRST)
    print("[*] Conexión terminada")

def connectedSend(pkt):
    """Envía paquete dentro de conexión TCP establecida"""
    pkt[TCP].flags = 'PA'
    pkt[TCP].seq = seqNr
    pkt[TCP].ack = ackNr
    send(pkt)

# ============================================
# EJECUCIÓN PRINCIPAL
# ============================================

print("="*50)
print("MODBUS TCP COMMUNICATION WITH SCAPY")
print("="*50)

# Paso 1: Establecer conexión TCP
ConnectionPkt = tcpHandshake()

# Paso 2: Crear paquete Modbus para leer coils
ModbusPkt = ConnectionPkt/ModbusADU()/ModbusPDU01_Read_Coils()

# Configurar parámetros Modbus
ModbusPkt[ModbusADU].unitId = 1
ModbusPkt[ModbusPDU01_Read_Coils].funcCode = 1
ModbusPkt[ModbusPDU01_Read_Coils].quantity = 5

# Paso 3: Enviar 5 solicitudes con diferentes direcciones
print("\n[*] Enviando solicitudes Modbus...")

for i in range(1, 6):
    # ID de transacción único
    ModbusPkt[ModbusADU].transId = transID + i*3
    ModbusPkt[ModbusPDU01_Read_Coils].startAddr = random.randint(0, 100)

    print(f"\n--- Request {i} ---")

    # Enviar paquete
    connectedSend(ModbusPkt)

    # Esperar respuesta
    Results = sniff(count=1, filter='tcp[tcpflags] & (tcp-push|tcp-ack) != 0', timeout=5)

    if Results:
        ResponsePkt = Results[0]
        updateSeqAndAckNrs(ModbusPkt, ResponsePkt)
        print("[+] Respuesta recibida:")
        ResponsePkt.show()
        sendAck()
    else:
        print("[-] No se recibió respuesta")

# Paso 4: Terminar conexión
endConnection()

print("\n" + "="*50)
print("COMUNICACIÓN COMPLETADA")
print("="*50)