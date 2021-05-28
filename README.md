# SNMP_V3-Basic_Frame-Over-Ethernet-Layer-Python
Basic snmp_v3 frame over ethernet layer for client side, ethernet type 0x814C, Linux only, python 3

Not support set security flag or version
Not support encryption yet
With the code can achieve basic functions, get and set

Below is the instruction about how to use the class.
``` python3
# First import class and create instance
import SNMPpacket
instance = SNMP()

# Second Basic Information Configuration
# set network interface or use "eth0" in deafult
instance.set_network_interface("eth1")
# set destination MAC of the SNMP server, assign the argument as a list with hex or intger
instance.set_dst([0xff,0xff,0xff,0xff,0xff,0xff])
# you may also set the source MAC (Optional, to set a different source MAC or use the MAC as the interface you set)
instance.set_src([0x00,0x60,0x65,0x08,0x51,0xc5])
# set security parameter, if do not include one, just set as None
instance.set_security_parameter(authEngineID:str,authEngineBoots:int,authEngineTime:int,userName:str,authParameters:str,privacyParameters:str)
# set pdu context engine
instance.set_PDU(contextEngineID:str, contextName:str)

# Third Construct SNMP Payload
# SNMP_create(operation:int,OID list:list, OID type:list, OID value:list)
# operation can be 0xa0 for get request, 0xa3 for set request
# when 0xa0, can get multiple OID, OID list = [[OID1],[OID2],[OID3]], do not need OID type and OID value
payload = instance.SNMP_create(0xa0,[[0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xe5, 0x00, 0x01,0x05,0x08,0x00],[0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xe5, 0x00, 0x01,0x05,0x08,0x00]])
# when 0xa3, better set one by one, can also set mulitple, type and vlaue will be needed. Type (4:string, 2:intger)
payload = instance.SNMP_create(0xa3,[[0x2b, 0x06, 0x01, 0x04, 0x01, 0x81, 0xe5, 0x00, 0x01,0x05,0x08,0x00]],[4],[0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x32,0x2e,0x31,0x31,0x32])

# Fourth Send Payload
instance.send_ether(payload)

# Fifth Read response
instance.pack_read(instance.packet_recv(1024))
```
