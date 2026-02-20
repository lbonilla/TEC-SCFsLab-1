# Scripts del Laboratorio Modbus

## Archivos

| Script | Ejecutar en | Descripcion |
|--------|-------------|-------------|
| `Modbus_server.py` | Ubuntu (192.168.1.66) | Servidor Modbus TCP |
| `Modbus_client_scapy.py` | Kali (192.168.1.64) | Cliente Modbus con Scapy |
| `Modbus_replay.py` | Kali (192.168.1.64) | Herramienta de replay de paquetes |

---

## 1. Servidor Modbus (Ubuntu)

### Instalacion
```bash
sudo apt update
sudo apt install python3-pip -y
sudo pip3 install pymodbus
```

### Ejecucion
```bash
sudo python3 Modbus_server.py
```

### Salida esperada
```
==================================================
MODBUS TCP SERVER
==================================================
Vendor:  PyModbus Inc.
Product: Modbus Server 1.0
Address: 0.0.0.0:502
==================================================
Servidor iniciado. Presione Ctrl+C para detener.
==================================================
```

---

## 2. Cliente Modbus con Scapy (Kali)

### Instalacion
```bash
sudo apt update
sudo apt install python3-pip -y
sudo pip3 install scapy
```

### Prerequisito: Deshabilitar RST automatico
```bash
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.64 -j DROP
```

### Ejecucion
```bash
sudo python3 Modbus_client_scapy.py
```

### Funcionalidades
- Establecer conexion TCP manualmente (three-way handshake)
- Leer Coils (FC=01)
- Leer Holding Registers (FC=03)
- Escribir Single Coil (FC=05)

---

## 3. Herramienta de Replay (Kali)

### Ejecucion
```bash
sudo python3 Modbus_replay.py
```

### Modos disponibles
1. **Demo automatico**: Envia paquetes predefinidos y los modifica
2. **Modo interactivo**: Permite ingresar hex streams de Wireshark
3. **Captura**: Captura paquetes Modbus de la red

### Uso con Wireshark
1. Capturar trafico en Wireshark con filtro: `tcp.port == 502`
2. Click derecho en paquete Modbus → Copy → ...as a Hex Stream
3. Ejecutar script en modo interactivo
4. Pegar hex stream (solo parte Modbus, sin headers Ethernet/IP/TCP)

---

## Comandos utiles

### Verificar conectividad
```bash
ping 192.168.1.66
```

### Verificar puerto abierto
```bash
nmap -p 502 192.168.1.66
```

### Usar modbus-cli (alternativa)
```bash
# Leer coils
modbus read 192.168.1.66 %M1 5

# Leer holding registers
modbus read 192.168.1.66 400001 5

# Escribir valor
modbus write 192.168.1.66 400001 100
```

### Revertir regla iptables
```bash
sudo iptables -D OUTPUT -p tcp --tcp-flags RST RST -s 192.168.1.64 -j DROP
```

---

## Troubleshooting

### Error: "No se recibio SYN/ACK"
- Verificar que el servidor este corriendo en Ubuntu
- Verificar conectividad de red entre las VMs
- Verificar que el puerto 502 no este bloqueado por firewall

### Error: Conexion se resetea inmediatamente
- Asegurarse de ejecutar la regla iptables para bloquear RST
- Ejecutar los scripts con `sudo`

### Error: "Permission denied"
- Los scripts requieren permisos de root para manipular paquetes
- Usar `sudo python3 script.py`
