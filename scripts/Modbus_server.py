#!/usr/bin/env python3
"""
Modbus TCP Server - Para ejecutar en Ubuntu (192.168.1.66)

Servidor Modbus TCP usando pyModbus 3.x
Este servidor simula un dispositivo industrial con registros accesibles.

Uso:
    sudo python3 Modbus_server.py
"""

from pymodbus.server import StartTcpServer
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)


def run_server():
    """Inicia el servidor Modbus TCP"""

    # Crear bloques de datos con valor inicial 17 (100 registros cada uno)
    # Discrete Inputs (read-only bits)
    di_block = ModbusSequentialDataBlock(0, [17]*100)
    # Coils (read-write bits)
    co_block = ModbusSequentialDataBlock(0, [17]*100)
    # Holding Registers (read-write 16-bit)
    hr_block = ModbusSequentialDataBlock(0, [17]*100)
    # Input Registers (read-only 16-bit)
    ir_block = ModbusSequentialDataBlock(0, [17]*100)

    # Crear contexto del esclavo
    slave_context = ModbusSlaveContext(
        di=di_block,
        co=co_block,
        hr=hr_block,
        ir=ir_block
    )

    # Crear contexto del servidor (single=True significa un solo esclavo)
    server_context = ModbusServerContext(slaves=slave_context, single=True)

    # Mostrar informacion del servidor
    print("=" * 50)
    print("MODBUS TCP SERVER")
    print("=" * 50)
    print("Vendor:  PyModbus Inc.")
    print("Product: Modbus Server 1.0")
    print("Address: 0.0.0.0:502")
    print("=" * 50)
    print("Registros inicializados con valor: 17")
    print("Cantidad de registros: 100 por tipo")
    print("=" * 50)
    print("Servidor iniciado. Presione Ctrl+C para detener.")
    print("=" * 50)

    # Iniciar servidor TCP en puerto 502
    StartTcpServer(
        context=server_context,
        address=("0.0.0.0", 502)
    )


if __name__ == "__main__":
    run_server()
