#!/usr/bin/env python3
"""
Modbus TCP Server - Para ejecutar en Ubuntu (192.168.1.66)

Servidor Modbus TCP usando pyModbus 2.5.3

Instalacion:
    pip3 install pymodbus==2.5.3

Uso:
    python3 Modbus_server.py
"""

from pymodbus.server.sync import StartTcpServer
from pymodbus.datastore import ModbusSequentialDataBlock
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.device import ModbusDeviceIdentification

# Puerto del servidor (5020 no requiere sudo, 502 requiere sudo)
PORT = 5020


def run_server():
    """Inicia el servidor Modbus TCP"""

    # Crear datastore con datos de prueba (valor 17 en 100 registros)
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [17]*100),  # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [17]*100),  # Coils
        hr=ModbusSequentialDataBlock(0, [17]*100),  # Holding Registers
        ir=ModbusSequentialDataBlock(0, [17]*100)   # Input Registers
    )

    context = ModbusServerContext(slaves=store, single=True)

    # Configurar identificacion del servidor
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'PyModbus Inc.'
    identity.ProductCode = 'PM'
    identity.VendorUrl = 'https://github.com/pymodbus-dev/pymodbus'
    identity.ProductName = 'Modbus Server'
    identity.ModelName = 'PyModbus'
    identity.MajorMinorRevision = '1.0'

    # Mostrar informacion
    print("=" * 50)
    print("MODBUS TCP SERVER")
    print("=" * 50)
    print(f"Vendor:  {identity.VendorName}")
    print(f"Product: {identity.ProductName} {identity.MajorMinorRevision}")
    print(f"Address: 0.0.0.0:{PORT}")
    print("=" * 50)
    print("Servidor iniciado. Presione Ctrl+C para detener.")
    print("=" * 50)

    # Iniciar servidor
    StartTcpServer(context, identity=identity, address=("0.0.0.0", PORT))


if __name__ == "__main__":
    run_server()
