from scapy.all import *                                                                                          
from Modbus.Modbus import *                                                                                      
import random                                                                                                    
                                                                                                                
# Configuración                                                                                                  
srcIP = '192.168.1.64'                                                                                           
dstIP = '192.168.1.66'                                                                                           
dstPort = 5020                                                                                                   
srcPort = random.randint(1024, 65535)                                                                            
seqNr = random.randint(1000, 9000000)                                                                            
                                                                                                                
# Paso 1: TCP Handshake                                                                                          
ip = IP(src=srcIP, dst=dstIP)                                                                                    
syn = TCP(sport=srcPort, dport=dstPort, flags='S', seq=seqNr)                                                    
syn_ack = sr1(ip/syn)                                                                                            
                                                                                                                
# Paso 2: Completar handshake                                                                                    
seqNr += 1                                                                                                       
ackNr = syn_ack.seq + 1                                                                                          
ack = TCP(sport=srcPort, dport=dstPort, flags='A', seq=seqNr, ack=ackNr)                                         
send(ip/ack)                                                                                                     
                                                                                                                
# Paso 3: Enviar paquete Modbus                                                                                  
modbus = ModbusADU(transId=0x1234, unitId=1)                                                                     
pdu = ModbusPDU03_Read_Holding_Registers(startAddr=0, quantity=5)                                                
                                                                                                                
modbus_pkt = ip/TCP(sport=srcPort, dport=dstPort, flags='PA', seq=seqNr, ack=ackNr)/modbus/pdu                   
response = sr1(modbus_pkt)                                                                                       
                                                                                                                
# Ver respuesta                                                                                                  
response.show()