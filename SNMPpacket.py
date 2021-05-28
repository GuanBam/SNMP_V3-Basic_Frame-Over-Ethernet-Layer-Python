# for linux OS only
# SOCK_RAW only works for Linux

from socket import *
import struct
import time

class SNMP():

    def __init__(self):
        # initialize socket with type raw
        self.snmp = socket(AF_PACKET, SOCK_RAW, htons(0x3))
        self.snmp.bind(('eth0', 0))
        self.dst = []
        self.src = []
        self.msgID = [0]
        self.msgAuthEngineID = []
        self.msgAuthEngineBoots = [0]
        self.msgAuthEngineTime = [0,0]
        self.msgUserName = []
        self.msgAuthParameters=[]
        self.msgPrivacyParameter=[]
        self.contextEngineID = []
        self.contextName = []
        self.msgDataRequestID = 1
        
    def set_network_interface(self, interface):
        # set network interface
        if type(interface) != str:
            print("Input Error: given value should be a string !")
            return
        try:
            import netifaces
            mac = netifaces.ifaddresses(interface)[netifaces.AF_PACKET][0]['addr'].split(":")
            src = []
            for i in mac:
                src += [int(i,16)]
             self.src = src
             self.snmp.bind((interface,0))
        except:
            print("Input Error: given interface is not found !")

    def set_dst(self, dst):
        # input checking
        assert (len(dst)==6)
        for i in dst:
            if i>255 or i<0 or type(i)!=int:
                print ("Wrong Destination MAC")
                return
        # assign value
        self.dst = dst

    def set_src(self,src):
        # input checking
        assert (len(dst)==6)
        for i in src:
            if i>255 or i<0 or type(i)!=int:
                print ("Wrong Source MAC")
                return
        # assign value
        self.src = src
        
    def set_security_parameter(self,authEngineID, authEngineBoots, authEngineTime, userName, authParameters,privacyParameters):
        # input checking
        assert authEngineID==None or type(authEngineID)==str
        assert authEngineBoots==None or type(authEngineBoots)==int
        assert authEngineTime==None or type(authEngineTime)==int
        assert userName == None or type(userName)==str
        assert authParameters==None or type(privacyParameter)==str
        # assign value
        self.msgAuthEngineID = [ord(x) for x in authEngineID]+[0] if authEngineID!=None else []
        self.msgAuthEngineBoots = self.int_to_list(authEngineBoots) if self.msgAuthEngineBoots != None else []
        self.msgAuthEngineTime = self.int_to_list(authEngineTime) if self.msgAuthEngineTime != None else [0,0]
        self.msgUserName =  [ord(x) for x in userName]+[0] if userName!=None else []
        self.msgAuthParameters= [ord(x) for x in authParameters]+[0] if authParameters!=None else []
        self.msgPrivacyParameter= [ord(x) for x in privacyParameters]+[0] if privacyParameters!=None else []

    def set_PDU(self, contextEngineID, contextName):
        # input checking
        assert contextEngineID==None or type(contextEngineID)==str
        assert contextName==None or type(contextName)==str
        # assign value
        self.contextEngineID = [ord(x) for x in contextEngineID]+[0] if contextEngineID!=None else []
        self.contextName = [ord(x) for x in contextName]+[0] if contextName!=None else []
        
    def int_to_list(self, value):
        assert type(value)==int
        temp = []
        while value>255:
            temp.insert(0,value%256)
            value //= 256
        temp.insert(0,value)
        return temp
    
    # send payload
    def send_ether(self, payload):
        protocolType = [0x81,0x4c]
        packet = self.dst+self.src+protocolType+payload
        raw = self.pack(packet)
        self.msgDataRequestID += 1
        return self.snmp.send(raw)

    def pack(self,hex_list):
        # convert list to byte string
        return struct.pack("%dB"%(len(hex_list)), *hex_list)
    
    # create ethernet payload
    def SNMP_create(self,operate=0xa0, OIDlist=[[]], OIDtype=[], OIDvalue=[[]]):
        #operate code:  a0--get-request;a1--get-next-request;a2--get-response;a3--set-request
        assert type(OIDlist) == list
        assert operate in [0xa0,0xa1,0xa2,0xa3]  
        if operate==0xa0:
            for i in range(len(OIDlist)):
                OIDtype.append(0x05)
                OIDvalue.append([])
        if operate==0xa3:
            assert len(OIDlist)==len(OIDtype)==len(OIDvalue)

        # snmp header
        msgVersion = [0x03]
        snmp_version=self.pack_snmphead(0x02,msgVersion)
        msgMaxSize = [0x05,0xdc]
        msgFlags = [0x04]
        msgSecurityModel = [0x03]
        snmp_v3_head = self.pack_snmphead(0x30,(self.pack_snmphead(0x02,self.msgID)\
                                           +self.pack_snmphead(0x02,msgMaxSize)\
                                           +self.pack_snmphead(0x04,msgFlags)\
                                           +self.pack_snmphead(0x02,msgSecurityModel)))
        # snmp security parameter
        snmp_security = self.pack_snmphead(0x04,(self.pack_snmphead(0x30,(self.pack_snmphead(0x04,self.int_to_list(self.msgAuthEngineID))\
                                                                +self.pack_snmphead(0x02,self.msgAuthEngineBoots)\
                                                                +self.pack_snmphead(0x02,self.msgAuthEngineTime)\
                                                                +self.pack_snmphead(0x04,self.msgUserName)\
                                                                +self.pack_snmphead(0x04,self.msgAuthParameters)\
                                                                +self.pack_snmphead(0x04,self.msgPrivacyParameter)))))
        ##### data #####
        errorStatus = [0x00]
        errorIndex = [0x00]
        # variable Binding store all the request OID,with value
        variableBinding=[]
        for i in range(len(OIDlist)):
            objectOID = OIDlist[i]
            item = self.pack_snmphead(0x06, objectOID)
            OIDwValue = item + self.pack_snmphead(OIDtype[i],OIDvalue[i])
            variableBinding += self.pack_snmphead(0x30,OIDwValue)
            
        PDUdata = self.pack_snmphead(operate,(self.pack_snmphead(0x02,self.msgDataRequestID)\
                                         +self.pack_snmphead(0x02,errorStatus)\
                                         +self.pack_snmphead(0x02,errorIndex)\
                                         +self.pack_snmphead(0x30,variableBinding)))
        snmp_PDU = self.pack_snmphead(0x30,(self.pack_snmphead(0x04,contextEngineID)\
                                  +self.pack_snmphead(0x04,contextName)\
                                  +PDUdata))
        SNMPpacket = self.pack_snmphead(0x30,snmp_version + snmp_v3_head + snmp_security + snmp_PDU)
        return SNMPpacket

    def pack_read(self,data):
        print("#########################")
        print("Ethernet Layer")
        Ethernet_packet = data[0:14]
        SNMP_packet = data[14:]
        Dst_MAC = Ethernet_packet[0:6]
        Src_MAC = Ethernet_packet[6:12]
        Payload_type = Ethernet_packet[12:14]
        print("dst = ",Dst_MAC)
        print("src = ",Src_MAC)
        print("type = ",Payload_type)
        print("#########################")
        print("SNMP Layer")
        ###remove SNMP head
        objectType,length,SNMPpacket=self.pack_decap(SNMP_packet)
        objectType,length,snmp_version,left_payload=self.pack_decap(SNMPpacket)
        print("snmp version = ",snmp_version)
        print("#########################")
        objectType,length,snmp_v3_header,left_payload=self.pack_decap(left_payload)
        print("SNMP V3 header length = ", length)
        objectType,length,msgID,left_v3_header=self.pack_decap(snmp_v3_header)
        print("    msgID = ",msgID)
        objectType,length,msgMaxSize,left_v3_header=self.pack_decap(left_v3_header)
        print("    msgMaxSize = ",msgMaxSize)
        objectType,length,msgFlags,left_v3_header=self.pack_decap(left_v3_header)
        print("    msgFlags = ",msgFlags)
        objectType,length,msgSecurityMode = self.pack_decap(left_v3_header)
        print("    msgSecurityMode = ",msgSecurityMode)
        print("#########################")
        #print(left_payload)
        objectType,length,security,left_payload = self.pack_decap(left_payload)
        print("SNMP Security Parameter length = ",length)
        objectType,length,security = self.pack_decap(security)
        objectType,length,AuthEngineID,left_security = self.pack_decap(security)
        print("    AuthEngineID = ",AuthEngineID)
        objectType,length,AuthEngineBoots,left_security = self.pack_decap(left_security)
        print("    AuthEngineBoots = ",AuthEngineBoots)
        objectType,length,AuthEngineTime,left_security = self.pack_decap(left_security)
        self.msgAuthEngineTime = AuthEngineTime
        print("    AuthEngineTime = ",AuthEngineTime)
        objectType,length,UserName,left_security = self.pack_decap(left_security)
        print("    User Name = ",UserName)
        objectType,length,AuthParameter,left_security=self.pack_decap(left_security)
        print("    AuthParameter = ",AuthParameter)
        objectType,length,PrivacyParameter = self.pack_decap(left_security)
        print("    PrivacyParameter =",PrivacyParameter)
        print("#########################")
        #print(left_payload)
        objectType,length,PDU=self.pack_decap(left_payload)
        print("PDU length = ",length)
        objectType,length,ContextEngineID,left_PDU = self.pack_decap(PDU)
        print("    ContextEngineID = ",ContextEngineID)
        objectType,length,ContextName,left_PDU = self.pack_decap(left_PDU)
        print("    ContextName = ",ContextName)
        objectType,length,PDUdata=self.pack_decap(left_PDU)
        print("    PDU data length = ",length)
        objectType,length,msgDataRequestID,left_PDU=self.pack_decap(PDUdata)
        print("        msgDataRequestID = ",msgDataRequestID)
        objectType,length,errorStatus,left_PDU=self.pack_decap(left_PDU)
        print("        errorStatus = ",errorStatus)
        objectType,length,errorIndex,left_PDU=self.pack_decap(left_PDU)
        print("        errorIndex = ",errorIndex)
        print(left_PDU)
        objectType,var_length,left_variableItem=self.pack_decap(left_PDU)
        print("variable binding length = ",var_length)
        while left_variableItem:
            try:
                objectType,length,variableItem,left_variableItem=self.pack_decap(left_variableItem)
            except ValueError:
                objectType,length,variableItem = self.pack_decap(left_variableItem)
                left_variableItem = False
            objectType,length,Item,value = self.pack_decap(variableItem)
            objectType,length,specific_value = self.pack_decap(value)
            print("OID: ",Item,"    type:",type,"    Value:",specific_value)

    def pack_snmphead(self,dataType,data):
        # each paremeter consisted by three parts, data type + length + data
        length = len(data)
        if len(data) > 0xff:
            data_len = [0x82,length//256,length%256]
        elif len(data)> 0x80:
            data_len = [0x81,length]
        else:
            data_len = [length]
        return ([dataType] + data_len + data)

    def pack_decap(self,data):
        # unpack data part by part
        objectType = data[0]
        raw_length = len(data)
        if data [1] <0x81:
            length = data[1]
            if length == raw_length:
                payload = data[2:]
            else:
                payload = data[2:length+2]
                left_payload = data[length+2:]
        elif data[1] == 0x81:
            length = data[2]
            if length == raw_length:
                payload = data[3:]
            else:
                payload = data[3:length+3]
                left_payload = data[length+3:]
        elif data[1] == 0x82:
            length = data[2]*256+data[3]
            if raw_length == length:
                payload = data[4:]
            else:
                payload = data[4:length+4]
                left_payload = data[length+4:]
        if left_payload:
            return objectType,length,payload,left_payload
        else:
            return objectType,length,payload

    def byte_to_list(self,bytes_data):
        result = []
        for i in bytes_data:
            result.append(i)
        return result

    # set timeout
    @set_timeout(5,after_timeout)
    def packet_recv(self,size):
        tmp = self.snmp.recv(size)
        while True:
            # check protocol type, if it's snmp, break loop and return
            if tmp[12] == 0x81 and tmp[13] == 0x4c:
                break
            else:
                tmp = self.snmp.recv(size)
        return tmp
