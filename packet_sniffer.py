import socket, sys
from struct import *

class PacketSniffer:
    '''
    Socket Module to capture the packets for all incoming
    and outgoing traffic via this 0x0003 either if write 
    socket.IPPROTO_TCP than it will accept just tcp traffic
    '''
    def __init__(self):
        try:
            self.s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
        except socket.error as msg:
            print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
            sys.exit()
    
    def recv_pkt(self):
        '''
        Recv Packets and parsing ethernet
        headers, also upacks them.
        
        socket.ntohs() --> function converts a 32 bit integer
        from network order to host order.If the host order is same as 
        network order, the function just executes a noop instruction.
        ntohl()will raise  an OverflowError  if a negative value is passed.
        
        refer-url: https://pythontic.com/modules/socket/byteordering-coversion-functions
        '''

        while True:
            packet = self.s.recvfrom(65565)
            
            #packet string from tuple
            packet = packet[0]
            eth_len = 14
            eth_header = packet[:eth_len]
            eth = unpack('!6s6sH', eth_header)
            
            eth_proto = socket.ntohs(eth[2])
            
            self.display(
                destination_MAC = self.eth_addr(packet[0:6]), 
                Source_MAC = self.eth_addr(packet[6:12]),
                Protocol = str(eth_proto) 
                )
            
            self._ip_header(packet, eth_len)
          
    def eth_addr(self,_pkt):
        '''
        Making Packets for manipulating 
        '''
        _pkt = str(_pkt)
        b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
            ord(_pkt[0]), ord(_pkt[1]), ord(_pkt[2]), 
            ord(_pkt[3]),ord(_pkt[4]), ord(_pkt[5])
            )
        
        
        return b
        
    def _ip_header(self, packet, eth_len):

        '''Ipheader unpacking
           Parse IP header
           take first 20 characters for the ip header
        '''
        ip_header = packet[eth_len:20 + eth_len]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF

        iph_length = ihl * 4

        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8])
        d_addr = socket.inet_ntoa(iph[9])
        
        self.make_dicison(
                    Version = version ,
                    IP_Header_Length = str(ihl),
                    TTL = str(ttl), 
                    Protocol = str(protocol),
                    Source_Address = str(s_addr), 
                    Destination_Address = str(d_addr),
                    iph_length = iph_length,
                    packet = packet,
                    eth_len = eth_len
                )
    
    def tcp_pkt_cap(self, iph_length, eth_length, packet):
        t = iph_length + eth_length
        tcp_header = packet[t:t+20]

        #now unpack them
        '''
        Each packets has its own hex values 
        so after unpacking them using struct
        that is C wrapper as mentioned in 
        readme.md file
        '''
        tcph = unpack('!HHLLBBHHH' , tcp_header)

        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        tcph_length = doff_reserved >> 4
        

        h_size = eth_length + iph_length + tcph_length * 4
        data_size = len(packet) - h_size

        #get data from the packet
        data = packet[h_size:]


        print('*' * 30, 'TCP Protocol', '*' * 30)


        self.display(
                        packet_proto='tcp',
                        Source_Port= str(source_port) ,
                        Dest_Port = str(dest_port) ,
                        Sequence_Number = str(sequence) ,
                        Acknowledgement = str(acknowledgement) ,
                        TCP_header_length = str(tcph_length),
                        Data = str(data)
                     )
        
    def icmp_pkt_cap(self, iph_length, eth_length, packet):
        '''
        ICMP (Internet Control Message Protocol) is an error-reporting 
        protocol that network devices such as routers use to generate 
        error messages to the source IP address when network problems prevent 
        delivery of IP packets.
        Url: https://www.techtarget.com/searchnetworking/definition/ICMP
         
        '''
        
        u = iph_length + eth_length
        icmph_length = 4
        icmp_header = packet[u:u+4]

        #now unpack them :)
        icmph = unpack('!BBH' , icmp_header)

        icmp_type = icmph[0]
        code = icmph[1]
        checksum = icmph[2]
        
        
        h_size = eth_length + iph_length + icmph_length
        data_size = len(packet) - h_size

        #get data from the packet
        data = packet[h_size:]

        print('*' * 30, 'ICMP Protocol', '*' * 30)


        self.display(
                        pakact_proto='icmp',
                        Type = str(icmp_type),
                        Code = str(code),
                        Checksum = str(checksum),
                        Data = str(data)
                    )

    def udp_pkt_cap(self,iph_length, eth_length, packet):
        '''
        In computer networking, the User Datagram Protocol (UDP) is one of
        the core members of the Internet protocol suite. With UDP, computer
        applications can send messages, in this case referred to as datagrams,
        to other hosts on an Internet Protocol (IP) network. Prior communications 
        are not required in order to set up communication channels or data paths.
        
        URL: https://en.wikipedia.org/wiki/User_Datagram_Protocol
        
        '''
        u = iph_length + eth_length
        udph_length = 8
        udp_header = packet[u:u+8]

        #now unpack them :)
        udph = unpack('!HHHH' , udp_header)

        source_port = udph[0]
        dest_port = udph[1]
        length = udph[2]
        checksum = udph[3]


        h_size = eth_length + iph_length + udph_length
        data_size = len(packet) - h_size

        #get data from the packet

        print('*' * 30, 'UDP Protocol', '*' * 30)

        self.display( 
                        SourcePort = str(source_port),
                        Dest_Port = str(dest_port),
                        Length = str(length),
                        Checksum = str(checksum),
                        data = str(packet[h_size:])
                    )
        
    def make_dicison(self, **kargs):
        '''
        TO control the flow of the program 
        here developed the member function
        so on run time the program easily
        makes decision to capture packets
        
        '''
        
        proto = {}
        
        for key, val in kargs.items():
            proto[key] = val
           
        protocol = int(proto['Protocol'])
        if protocol == 6:
            self.tcp_pkt_cap(proto['iph_length'], proto['eth_len'], proto['packet'])
            
        elif protocol == 1:
            self.icmp_pkt_cap(proto['iph_length'], proto['eth_len'], proto['packet'])
           
        elif protocol == 17:
            self.udp_pkt_cap(proto['iph_length'], proto['eth_len'], proto['packet'])

        else:
            print("Protocol Not Matched, Error %%%% ")
    
    def display(self, **kargs):
        for key,value in kargs.items():
            print(key, value)
            

if __name__ == "__main__":
    packet_sniffer = PacketSniffer()
    packet_sniffer.recv_pkt()