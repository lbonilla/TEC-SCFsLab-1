#!/usr/bin/env python3
"""
Modbus TCP Server - Para ejecutar en Ubuntu (192.168.1.66)

Servidor Modbus TCP usando pyModbus.
Este servidor simula un dispositivo industrial con registros accesibles.

Uso:
    sudo python3 Modbus_server.py
"""

# Importar segun version de pymodbus
try:
    # pymodbus v3.x (nueva version)
    from pymodbus.server import StartTcpServer
    from pymodbus.datastore import ModbusSequentialDataBlock
    from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
    from pymodbus.device import ModbusDeviceIdentification
    PYMODBUS_V3 = True
except ImportError:
    try:
        # pymodbus v2.x (version anterior)
        from pymodbus.server.sync import StartTcpServer
        from pymodbus.datastore import ModbusSequentialDataBlock
        from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
        from pymodbus.device import ModbusDeviceIdentification
        PYMODBUS_V3 = False
    except ImportError:
        print("ERROR: No se pudo importar pymodbus")
        print("Instalar con: sudo pip3 install pymodbus")
        exit(1)

def run_server():
    # Crear datastore con datos de prueba (valor 17 en 100 registros)
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [17]*100),  # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [17]*100),  # Coils
        hr=ModbusSequentialDataBlock(0, [17]*100),  # Holding Registers
        ir=ModbusSequentialDataBlock(0, [17]*100))  # Input Registers

    context = ModbusServerContext(slaves=store, single=True)

    # Configurar identificacion del servidor
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'PyModbus Inc.'
    identity.ProductCode = 'PM'
    identity.VendorUrl = 'https://github.com/pymodbus-dev/pymodbus'
    identity.ProductName = 'Modbus Server'
    identity.ModelName = 'PyModbus'
    identity.MajorMinorRevision = '1.0'

    # Mostrar informacion del servidor
    print("=" * 50)
    print("MODBUS TCP SERVER")
    print("=" * 50)
    print(f"Vendor:  {identity.VendorName}")
    print(f"Product: {identity.ProductName} {identity.MajorMinorRevision}")
    print(f"Address: 0.0.0.0:502")
    print(f"PyModbus version: {'3.x' if PYMODBUS_V3 else '2.x'}")
    print("=" * 50)
    print("Servidor iniciado. Presione Ctrl+C para detener.")
    print("=" * 50)

    # Iniciar servidor
    StartTcpServer(context=context, identity=identity, address=("0.0.0.0", 502))

if __name__ == "__main__":
    run_server()
