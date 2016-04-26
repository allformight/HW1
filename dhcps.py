import argparse, socket
import struct
from uuid import getnode as get_mac
from random import randint

MAX_BYTES = 65535


def getMacInBytes():
    mac = str(hex(get_mac()))
    mac = mac[2:]
    while len(mac) < 12 :
        mac = '0' + mac
    macb = b''
    for i in range(0, 12, 2) :
        m = int(mac[i:i + 2], 16)
        macb += struct.pack('!B', m)
    return macb


class DHCPDiscover:
    def __init__(self):
        self.transactionID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transactionID += struct.pack('!B', t) 

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transactionID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x01'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x3d\x06' + macb
        packet += b'\x37\x03\x03\x01\x06'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\xff'   #End Option
        return packet

class DHCPOffer:
    def __init__(self, data):
       # self.data = data
        self.transID = data[4:8]
       
        # self.offerIP = ''
        #self.nextServerIP = ''
        #self.DHCPServerIdentifier = ''
        #self.leaseTime = ''
        #self.router = ''
        #self.subnetMask = ''
        #self.DNS = []
        #self.unpack()

    
    #def unpack(self):
     #   if self.data[4:8] == self.transID :
      #      self.offerIP = '.'.join(map(lambda x:str(x), data[16:20]))
       #     self.nextServerIP = '.'.join(map(lambda x:str(x), data[20:24]))  #c'est une option
        #    self.DHCPServerIdentifier = '.'.join(map(lambda x:str(x), data[245:249]))
         #   self.leaseTime = str(struct.unpack('!L', data[251:255])[0])
          #  self.router = '.'.join(map(lambda x:str(x), data[257:261]))
           # self.subnetMask = '.'.join(map(lambda x:str(x), data[263:267]))
            #dnsNB = int(data[268]/4)
            #for i in range(0, 4 * dnsNB, 4):
             #   self.DNS.append('.'.join(map(lambda x:str(x), data[269 + i :269 + i + 4])))
                
    def printOffer(self):
        key = ['DHCP Server', 'Offered IP address', 'subnet mask', 'lease time (s)' , 'default gateway']
        val = [self.DHCPServerIdentifier, self.offerIP, self.subnetMask, self.leaseTime, self.router]
        for i in range(4):
            print('{0:20s} : {1:15s}'.format(key[i], val[i]))
        
        print('{0:20s}'.format('DNS Servers') + ' : ', end='')
        if self.DNS:
            print('{0:15s}'.format(self.DNS[0]))
        if len(self.DNS) > 1:
            for i in range(1, len(self.DNS)): 
                print('{0:22s} {1:15s}'.format(' ', self.DNS[i])) 

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x02'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\x6d\x2c'   #Your (client) IP address: 192.168.109.2c
        packet += b'\xc0\xa8\x6d\x87'   #Next server IP address: 192.168.109.254
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x02'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        packet += b'\x36\x04\xc0\xa8\x6d\xfe'   #Option: (t=54,l=6) server identifier
        packet += b'\x33\x04\x00\x00\x07\x08'    #(t=51)IP address lease time
        packet += b'\x03\x04\c0\a8\6d\02'    #Router
        packet += b'\x01\x04\xff\xff\xff\x00'   #Option: (t=55,l=3) Parameter Request List
        packet += b'\x06\x04\c0\a8\6d\02'    #DNS
        packet += b'\xff'   #End Option
        return packet

class DHCPRequest:
    def __init__(self, data):
       # self.data = data
        self.transID = b''
        for i in range(4):
            t = randint(0, 255)
            self.transID += struct.pack('!B', t)

    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x01'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x85'   #Your (client) IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x87'   #Next server IP address: 0.0.0.0
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x03'   #Option: (t=53,l=3) DHCP Message Type = DHCP Request
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x32\x04\xc0\xa8\x6d\x2c'  #option50 client 192.168.109.44
        packet += b'\x36\x04\xc0\xa8\x6d\x87'  #option54 server 192.168.109.135
        packet += b'\xff'   #End Option
        return packet

class DHCPACK:
    def __init__(self, data):
       # self.data = data
        self.transID = data[4:8]


    def buildPacket(self):
        macb = getMacInBytes()
        packet = b''
        packet += b'\x02'   #Message type: Boot Request (1)
        packet += b'\x01'   #Hardware type: Ethernet
        packet += b'\x06'   #Hardware address length: 6
        packet += b'\x00'   #Hops: 0 
        packet += self.transID       #Transaction ID
        packet += b'\x00\x00'    #Seconds elapsed: 0
        packet += b'\x80\x00'   #Bootp flags: 0x8000 (Broadcast) + reserved flags
        packet += b'\x00\x00\x00\x00'   #Client IP address: 0.0.0.0
        packet += b'\xc0\xa8\x6d\x2c'   #Your (client) IP address: 192.168.109.2c
        packet += b'\xc0\xa8\x6d\x87'   #Next server IP address: 192.168.109.135
        packet += b'\x00\x00\x00\x00'   #Relay agent IP address: 0.0.0.0
        #packet += b'\x00\x26\x9e\x04\x1e\x9b'   #Client MAC address: 00:26:9e:04:1e:9b
        packet += macb
        packet += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'   #Client hardware address padding: 00000000000000000000
        packet += b'\x00' * 67  #Server host name not given
        packet += b'\x00' * 125 #Boot file name not given
        packet += b'\x63\x82\x53\x63'   #Magic cookie: DHCP
        packet += b'\x35\x01\x05'   #Option: (t=53,l=1) DHCP Message Type = DHCP Discover
        #packet += b'\x3d\x06\x00\x26\x9e\x04\x1e\x9b'   #Option: (t=61,l=6) Client identifier
        packet += b'\x33\x04\xc0\xa8\x6d\x2c'  #option51 client 192.168.109.44
        packet += b'\x36\x04\xc0\xa8\x6d\x87'  #option54 server 192.168.109.135
        packet += b'\x01\x04\xff\xff\xff\xff'   #DHCP optin:1 mask addr. 255.255.255.255 
        packet += b'\x03\x04\xc0\xa8\x6d\x87'   #router addr. 192.168.133.135
        
        packet += b'\xff'   #End Option
        return packet

def server():
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast 
    #buiding and sending the DHCPDiscover packet
    try:
        dhcps.bind(('0.0.0.0', 67))    
        print('Listening at {}'.format(dhcps.getsockname()))
        while True:
            data, address = dhcps.recvfrom(MAX_BYTES)
            print('receive data and address from client')
            print (data)
            print (address)
            print()

            #offer packet to client
            offerPacket=DHCPOffer(data)
            dhcps.sendto(offerPacket.buildPacket(),('255.255.255.255',1112))
            #get request message
            data3, address3 = dhcps.recvfrom(MAX_BYTES)
            print('receive data and address from client')
            print (data3)
            print (address3)
            print()
            #ack to client
            ACK= DHCPACK(data3);
            dhcps.sendto(ACK.buildPacket(),('255.255.255.255',1112) )  #port 1112

    except:
        print('port 67 in use...')
        dhcps.close()
        input('press any key to quit...')
        exit()





def client():
    dhcps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)    #internet, UDP
    dhcps.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1) #broadcast
    dhcps.bind(('0.0.0.0',1112))    #we want to send from port 1112
    discoverPacket = DHCPDiscover()
    dhcps.sendto(discoverPacket.buildPacket(), ('255.255.255.255', 67))  #port67
    #get offer message   
    data2, address2 = dhcps.recvfrom(MAX_BYTES)
    print('get offer message from server')
    print(data2)
    print(address2)
    print()
    # #send request mes.
    request = DHCPRequest(data2)
    dhcps.sendto(request.buildPacket(),('255.255.255.255',67))   #port67

    #get ack
    data4, address4 = dhcps.recvfrom(MAX_BYTES)
    print('get ack message from server')
    print(data4)
    print(address4)
    print()
    

            
    # print('DHCP Discover sent waiting for reply...\n')
    # while True:
    #     sock.sendto(data,('255.255.255.255', 67))
    #     data, address = sock.recvfrom(MAX_BYTES)
    #     print('123132132123')
     #buiding and sending the DHCPDiscover packet
    
   

if __name__ == '__main__':
    choices = {'client': client,'server': server}
    parser = argparse.ArgumentParser(description='Send and receive UDP locally')
    parser.add_argument('role', choices=choices, help='which role to play')
    args = parser.parse_args()
    function = choices[args.role]
    function()
