# Guía de Laboratorio: Análisis de Seguridad Modbus TCP/IP

> **Curso**: MC4002 Seguridad en Sistemas Ciberfísicos
> **Caso de Estudio #1**: Modbus
> **Fecha de Entrega**: Miércoles 25 de Febrero 2026, 16:00

---

## Configuración del Entorno

### Máquinas Virtuales Requeridas

| Máquina | Sistema Operativo | Rol | IP Sugerida |
|---------|-------------------|-----|-------------|
| **VM1** | Ubuntu Linux | Servidor Modbus | `192.168.1.66` |
| **VM2** | Kali Linux | Atacante/Analizador | `192.168.1.64` |

> **Importante**: Ambas VMs deben estar en la misma red virtual (NAT Network o Host-Only)

---

## PARTE 1: Breaking Modbus

### 1.1 Instalación de Paquetes

---

#### 🖥️ EN UBUNTU (VM1 - Servidor)

```bash
# Actualizar sistema
sudo apt update

# Instalar pip para Python
sudo apt-get install python3-pip -y

# Instalar pyModbus
sudo pip3 install pymodbus
```

---

#### 🔴 EN KALI (VM2 - Atacante)

```bash
# Instalar Ruby (requerido para modbus-cli)
sudo apt update
sudo apt install ruby ruby-dev -y

# Instalar modbus-cli (cliente Ruby)
sudo gem install modbus-cli

# Verificar instalación
modbus -h
```

---

### 1.2 Crear y Ejecutar Servidor Modbus

#### 🖥️ EN UBUNTU (VM1 - Servidor)

**Crear el archivo del servidor:**

```bash
nano Modbus_server.py
```

**Copiar el siguiente código:**

```python
#!/usr/bin/env python3
'''
Modbus TCP Server usando pyModbus
'''
# Importar librerias
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext

# Create a datastore and populate it with test data
store = ModbusSlaveContext(
    di = ModbusSequentialDataBlock(0, [17]*100),  # Discrete Inputs initializer
    co = ModbusSequentialDataBlock(0, [17]*100),  # Coils initializer
    hr = ModbusSequentialDataBlock(0, [17]*100),  # Holding Register initializer
    ir = ModbusSequentialDataBlock(0, [17]*100))  # Input Registers initializer

context = ModbusServerContext(slaves=store, single=True)

# Populate the Modbus server information fields
identity = ModbusDeviceIdentification()
identity.VendorName = 'PyModbus Inc.'
identity.ProductCode = 'PM'
identity.VendorUrl = 'https://github.com/riptideio/pyModbus'
identity.ProductName = 'Modbus Server'
identity.ModelName = 'PyModbus'
identity.MajorMinorRevision = '1.0'

# Start the listening server
print("Starting Modbus server...")
StartTcpServer(context, identity=identity, address=("0.0.0.0", 502))
```

**Ejecutar el servidor:**

```bash
sudo python3 Modbus_server.py
```

> ⚠️ **Mantener esta terminal abierta** - El servidor debe estar corriendo para las pruebas

**📸 SCREENSHOT**: Capturar pantalla mostrando "Starting Modbus server..."

---

### 1.3 Probar Conexión con modbus-cli

#### 🔴 EN KALI (VM2 - Atacante)

**Leer estado de Coils (memoria bit %M):**

```bash
modbus read 192.168.1.66 %M1 5
```

**Resultado esperado:**
```
%M1     1
%M2     1
%M3     1
%M4     1
%M5     1
```

**📸 SCREENSHOT**: Capturar el resultado de lectura

**Leer Input Registers:**

```bash
modbus read 192.168.1.66 1 5
```

**Leer Holding Registers con formato word:**

```bash
modbus read --word 192.168.1.66 400001 10
```

**Escribir un valor (demostrar falta de autenticación):**

```bash
# Escribir 0 en la posición 1
modbus write 192.168.1.66 1 0

# Verificar el cambio
modbus read 192.168.1.66 1 5
```

**📸 SCREENSHOT**: Capturar escritura y verificación

---

### 1.4 Escaneo de Red con Nmap

#### 🔴 EN KALI (VM2 - Atacante)

**Descubrir hosts activos en la red:**

```bash
nmap -sP 192.168.1.0/24
```

**📸 SCREENSHOT**: Capturar hosts descubiertos

**Escanear puertos del servidor Modbus:**

```bash
nmap -A 192.168.1.66
```

**Escanear TODOS los puertos TCP:**

```bash
nmap -A 192.168.1.66 -p-
```

**📸 SCREENSHOT**: Capturar resultado mostrando puerto 502/tcp open mbap

**Usar script NSE para descubrir información Modbus:**

```bash
nmap 192.168.1.66 -p 502 --script modbus-discover.nse
```

**Resultado esperado:**
```
PORT     STATE SERVICE
502/tcp  open  Modbus
| Modbus-discover:
|   sid 0x1:
|     error: SLAVE DEVICE FAILURE
|_    Device identification: PyModbus Inc. PM 1.0
```

**📸 SCREENSHOT**: Capturar información del dispositivo descubierta

---

## PARTE 2: Using Python and Scapy to Communicate over Modbus

### 2.1 Preparar Módulos de Scapy para Modbus

#### 🔴 EN KALI (VM2 - Atacante)

**Descargar framework smod:**

```bash
# Opción 1: Clonar desde GitHub
git clone https://github.com/enddo/smod.git

# Opción 2: Si el repo no está disponible, buscar alternativas
# Buscar "smod modbus scapy" en GitHub
```

**Copiar módulos al directorio de Python:**

```bash
# Crear directorio para módulos Modbus
sudo mkdir -p /usr/lib/python2.7/dist-packages/Modbus/

# Copiar archivos del framework
sudo cp smod-master/System/Core/*.py /usr/lib/python2.7/dist-packages/Modbus/
```

> **Nota**: Si usas Python 3, ajusta la ruta a `/usr/lib/python3/dist-packages/Modbus/`

---

### 2.2 Pruebas Básicas con Scapy

#### 🔴 EN KALI (VM2 - Atacante)

**Iniciar Scapy:**

```bash
sudo scapy
```

**Crear un paquete IP/TCP básico:**

```python
>>> ip = IP(src='192.168.1.64', dst='192.168.1.66')
>>> tcp = TCP(sport=12345, dport=502, flags='S')
>>> pkt = ip/tcp
>>> pkt.show()
```

**📸 SCREENSHOT**: Capturar estructura del paquete

**Enviar paquete y capturar respuesta:**

```python
>>> answer = sr1(pkt)
>>> answer.show()
```

**📸 SCREENSHOT**: Capturar respuesta SYN/ACK

---

### 2.3 Deshabilitar RST Automático

#### 🔴 EN KALI (VM2 - Atacante)

> **Importante**: Linux envía RST automáticamente para paquetes SYN forjados. Debemos deshabilitarlo.

```bash
# Ejecutar ANTES de los scripts de Scapy
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.64 -j DROP
```

**Para revertir después del laboratorio:**

```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.64 -j DROP
```

---

### 2.4 Crear Paquetes Modbus con Scapy

#### 🔴 EN KALI (VM2 - Atacante)

**En Scapy, importar módulos y crear paquete Modbus:**

```python
>>> from Modbus.Modbus import *
>>> pkt = ip/tcp/ModbusADU()/ModbusPDU01_Read_Coils()
>>> pkt[ModbusADU].show()
```

**Ver PDUs disponibles (presionar TAB dos veces):**

```python
>>> pkt = ip/tcp/ModbusADU()/ModbusPDU
# Presionar TAB TAB para ver opciones
```

**PDUs disponibles:**
- `ModbusPDU01_Read_Coils`
- `ModbusPDU02_Read_Discrete_Inputs`
- `ModbusPDU03_Read_Holding_Registers`
- `ModbusPDU04_Read_Input_Registers`
- `ModbusPDU05_Write_Single_Coil`
- `ModbusPDU06_Write_Single_Register`
- `ModbusPDU0F_Write_Multiple_Coils`
- `ModbusPDU10_Write_Multiple_Registers`

---

### 2.5 Script Completo de Comunicación Modbus

#### 🔴 EN KALI (VM2 - Atacante)

**Crear archivo `modbus_communication.py`:**

```bash
nano modbus_communication.py
```

**Copiar el siguiente código:**

```python
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
dstPort  = 502
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
```

**Ejecutar el script:**

```bash
sudo python modbus_communication.py
```

**📸 SCREENSHOT**: Capturar la ejecución mostrando solicitudes y respuestas

---

## PARTE 3: Replaying Captured Modbus Packets

### 3.1 Capturar Tráfico con Wireshark

#### 🔴 EN KALI (VM2 - Atacante)

**Paso 1: Iniciar Wireshark**

```bash
sudo wireshark &
```

**Paso 2: Seleccionar interfaz de red** (eth0 o la que corresponda)

**Paso 3: En otra terminal, generar tráfico Modbus:**

```bash
nmap 192.168.1.66 -p 502 --script modbus-discover.nse
```

**Paso 4: En Wireshark, aplicar filtro:**

```
ip.addr== 192.168.1.66 && tcp.port == 502
```

**📸 SCREENSHOT**: Capturar Wireshark con paquetes Modbus filtrados

---

### 3.2 Exportar Paquete como Hex Stream

#### 🔴 EN KALI (VM2 - Atacante)

**En Wireshark:**

1. Seleccionar un paquete **Modbus Query** (Request)
2. Click derecho sobre el paquete
3. Seleccionar: **Copy → ...as a Hex Stream**

**📸 SCREENSHOT**: Capturar el menú de copia

---

### 3.3 Importar y Manipular Paquete en Scapy

#### 🔴 EN KALI (VM2 - Atacante)

**Iniciar Scapy:**

```bash
sudo scapy
```

**Importar módulos necesarios:**

```python
>>> from Modbus.Modbus import *
>>> import binascii
```

**Convertir hex stream a paquete Scapy:**

```python
# Pegar el hex stream copiado de Wireshark
>>> raw_pkt = binascii.unhexlify('PEGAR_HEX_STREAM_AQUI')

# Convertir a paquete Scapy (comenzando desde Ethernet)
>>> Modbus_pkt = Ether(raw_pkt)

# Ver estructura del paquete
>>> Modbus_pkt.show()
```

**Ejemplo de salida:**
```
###[ Ethernet ]###
  dst= 00:0c:29:8f:79:2c
  src= 00:0c:29:f2:7e:ce
  type= 0x800
###[ IP ]###
  ...
###[ TCP ]###
  sport= 44828
  dport= 502
  ...
###[ ModbusADU ]###
  transId= 0x0
  protoId= 0x0
  len= 0x2
  unitId= 0x1
###[ Report Slave Id ]###
  funcCode= 0x11
```

**📸 SCREENSHOT**: Capturar la estructura del paquete importado

---

### 3.4 Modificar y Reenviar Paquete

#### 🔴 EN KALI (VM2 - Atacante)

**Modificar campos del paquete:**

```python
# Cambiar Transaction ID
>>> Modbus_pkt[ModbusADU].transId = 0x1234

# Cambiar dirección de inicio (si aplica)
>>> Modbus_pkt[ModbusPDU01_Read_Coils].startAddr = 10

# Ver cambios
>>> Modbus_pkt[ModbusADU].show()
```

**Nota**: Para reenviar sobre TCP, usar las funciones del script de la Parte 2.

**📸 SCREENSHOT**: Capturar paquete modificado

---

## Referencia Rápida: Códigos de Función Modbus

| FC (Hex) | FC (Dec) | Descripción |
|----------|----------|-------------|
| 0x01 | 1 | Read Coil Status |
| 0x02 | 2 | Read Discrete Inputs |
| 0x03 | 3 | Read Holding Registers |
| 0x04 | 4 | Read Input Registers |
| 0x05 | 5 | Write Single Coil |
| 0x06 | 6 | Write Single Holding Register |
| 0x07 | 7 | Read Exception Status |
| 0x0F | 15 | Write Multiple Coils |
| 0x10 | 16 | Write Multiple Holding Registers |
| 0x11 | 17 | Report Slave ID |
| 0x2B | 43 | Read Device Identification |

---

## Referencia: Tipos de Datos modbus-cli

| Tipo de Dato | Tamaño | Dirección Schneider | Dirección Modicon | Parámetro |
|--------------|--------|---------------------|-------------------|-----------|
| Words (unsigned) | 16 bits | %MW1 | 400001 | `--word` |
| Integer (signed) | 16 bits | %MW1 | 400001 | `--int` |
| Floating point | 32 bits | %MF1 | 400001 | `--float` |
| Double words | 32 bits | %MD1 | 400001 | `--dword` |
| Boolean (coils) | 1 bit | %M1 | 400001 | N/A |

---

## Checklist de Screenshots Requeridos

- [ ] Servidor Modbus iniciado (Ubuntu)
- [ ] Lectura de coils con modbus-cli (Kali)
- [ ] Escritura de valores con modbus-cli (Kali)
- [ ] Escaneo Nmap mostrando puerto 502 abierto (Kali)
- [ ] Script modbus-discover.nse revelando información del dispositivo (Kali)
- [ ] Paquete IP/TCP creado en Scapy (Kali)
- [ ] Respuesta SYN/ACK capturada (Kali)
- [ ] Ejecución del script de comunicación Modbus (Kali)
- [ ] Wireshark con tráfico Modbus capturado (Kali)
- [ ] Paquete importado desde hex stream en Scapy (Kali)
- [ ] Paquete Modbus modificado (Kali)

---

## Vulnerabilidades Demostradas

1. **Sin Encriptación**: Todo el tráfico Modbus se transmite en texto plano
2. **Sin Autenticación**: No se requieren credenciales para leer/escribir
3. **Sin Integridad**: Los paquetes pueden ser modificados sin detección
4. **Información Expuesta**: Nmap puede obtener información del dispositivo

---

## Solución de Problemas

### El servidor Modbus no inicia
```bash
# Verificar que el puerto 502 no está en uso
sudo netstat -tlnp | grep 502

# Ejecutar con Python 2 si hay problemas de compatibilidad
sudo python2 Modbus_server.py
```

### modbus-cli no puede conectar
```bash
# Verificar conectividad
ping 192.168.1.66

# Verificar que el servidor está corriendo
nmap -p 502 192.168.1.66
```

### Scapy no encuentra módulos Modbus
```bash
# Verificar ubicación de módulos
ls /usr/lib/python2.7/dist-packages/Modbus/

# Si usas Python 3
ls /usr/lib/python3/dist-packages/Modbus/
```

### RST packets interfieren con Scapy
```bash
# Asegurarse de ejecutar la regla iptables
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s TU_IP_KALI -j DROP
```

---

## Notas Finales

> **Recuerda**: Todos los screenshots deben mostrar la **fecha y hora del sistema** visible en pantalla completa como control anti-plagio.

> **Fecha de entrega**: Miércoles 25 de Febrero 2026 a las 16:00 - Subir al TecDigital
