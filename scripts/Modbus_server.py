#!/usr/bin/env python3
"""
Modbus TCP Server - Para ejecutar en Ubuntu (192.168.1.66)

Servidor Modbus TCP usando pyModbus.
Este servidor simula un dispositivo industrial con registros accesibles.

Uso:
    sudo python3 Modbus_server.py
"""

import sys

# Detectar version de pymodbus e importar correctamente
try:
    import pymodbus
    version = pymodbus.__version__
    major_version = int(version.split('.')[0])
    print(f"[*] pymodbus version: {version}")
except:
    major_version = 3  # Asumir v3

if major_version >= 3:
    # pymodbus v3.x
    try:
        from pymodbus.server import StartTcpServer
        from pymodbus.datastore import (
            ModbusSequentialDataBlock,
            ModbusSlaveContext,
            ModbusServerContext,
        )
        print("[*] Usando imports de pymodbus v3.x")
    except ImportError as e:
        print(f"ERROR importando pymodbus v3: {e}")
        sys.exit(1)
else:
    # pymodbus v2.x
    try:
        from pymodbus.server.sync import StartTcpServer
        from pymodbus.datastore import (
            ModbusSequentialDataBlock,
            ModbusSlaveContext,
            ModbusServerContext,
        )
        from pymodbus.device import ModbusDeviceIdentification
        print("[*] Usando imports de pymodbus v2.x")
    except ImportError as e:
        print(f"ERROR importando pymodbus v2: {e}")
        sys.exit(1)


def run_server():
    """Inicia el servidor Modbus TCP"""

    # Crear datastore con datos de prueba (valor 17 en 100 registros)
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [17]*100),  # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [17]*100),  # Coils
        hr=ModbusSequentialDataBlock(0, [17]*100),  # Holding Registers
        ir=ModbusSequentialDataBlock(0, [17]*100))  # Input Registers

    context = ModbusServerContext(slaves=store, single=True)

    # Mostrar informacion del servidor
    print("=" * 50)
    print("MODBUS TCP SERVER")
    print("=" * 50)
    print("Vendor:  PyModbus Inc.")
    print("Product: Modbus Server 1.0")
    print("Address: 0.0.0.0:502")
    print("=" * 50)
    print("Servidor iniciado. Presione Ctrl+C para detener.")
    print("=" * 50)

    # Iniciar servidor (sintaxis difiere entre versiones)
    if major_version >= 3:
        StartTcpServer(context=context, address=("0.0.0.0", 502))
    else:
        identity = ModbusDeviceIdentification()
        identity.VendorName = 'PyModbus Inc.'
        identity.ProductCode = 'PM'
        identity.ProductName = 'Modbus Server'
        identity.ModelName = 'PyModbus'
        identity.MajorMinorRevision = '1.0'
        StartTcpServer(context=context, identity=identity, address=("0.0.0.0", 502))


if __name__ == "__main__":
    run_server()
