## Packet Sniffer

A packet sniffer — also known as a packet analyzer, protocol analyzer or network analyzer. 
— Is a piece of hardware or software used to monitor network traffic. Sniffers work by examining 
streams of data packets that flow between computers on a network as well as between networked
computers and the larger Internet. 

— These packets are intended for Addressed to specific machines, but using a packet sniffer in
"promiscuous mode" allows IT professionals, end users or malicious intruders to examine any 
packet, regardless of destination. It's possible to configure sniffers in two ways. The first 
is "unfiltered," meaning they will capture all packets possible and write them to a local hard 
drive for later examination. Next is "filtered" mode, meaning analyzers will only capture 
packets that contain specific data elements.


## Socket — Low-level networking interface 
This module provides access to the BSD socket interface. It is available on all modern Unix systems,
Windows, MacOS, and probably additional platforms.

The Python interface is a straightforward transliteration of the Unix system call and library interface 
for sockets to Python’s object-oriented style: the socket() function returns a socket object whose methods
implement the various socket system calls. Parameter types are somewhat higher-level than in the 
C interface: as with read() and write() operations on Python files, buffer allocation on receive operations 
is automatic, and buffer length is implicit on send operations.
    
    url: https://docs.python.org/3/library/socket.html

## Struct
This module performs conversions between Python values and C structs represented as Python bytes objects.
This can be used in handling binary data stored in files or from network connections, among other sources. 
It uses Format Strings as compact descriptions of the layout of the C structs and the intended conversion 
to/from Python values.


 https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers


## Request for Comments(RFC)
    RFC is also an abbreviation for Remote Function Call . A Request for Comments (RFC) is a formal document from the Internet Engineering Task Force ( IETF ) that is the result of committee drafting and subsequent review by interested parties. Some RFCs are informational in nature.

## PESUDO Code

class PacketSniffer:
    def __init__(self):
        start reciving packets

    def recv_packets(self):
        while True:
            Capture the incoming traffice header
            send them to Ip_header

   def eth_addr(pkt):
        make_packets in silicing in order to make
        the packet manipulation easy.
    
   def ip_header(self):
        unpacks the packets 
        and than analyze the protcol
        after 
        send to
        self.make_dicion(paramters)
    
    def make_decision(param):
        if proto == 6:
            tcp_pkt_cap
        elif proto == 1:
            icmp_pkt_cap()
        elif proto == 17:
            udp_pkt_cap()

    --> Why Protocol have numbers?
        'https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers'

    def tcp_pkt_cap(self):
        As Tcp header image is in
        doc folder

    def udp_pkt_cap(self):
        0      7 8     15 16    23 24    31  
        +--------+--------+--------+--------+ 
        |     Source      |   Destination   | 
        |      Port       |      Port       | 
        +--------+--------+--------+--------+ 
        |                 |                 | 
        |     Length      |    Checksum     | 
        +--------+--------+--------+--------+ 
        |                                     
        |          data octets ...            
        +---------------- ...

    def icmp_pkt_cap(self):
        0                   1                   2                   3
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                             unused                            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |      Internet Header + 64 bits of Original Data Datagram      |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


## Why OOP Paradigm:

    As Object Oriented Programming is real world paradigm
    in order to make projects scalable and than if user 
    or either client wants to add some extra features than
    we can easily add the funcationalt and extend features.

    Make decision is function avalaible in Program so 
    here cap the packet decision is performing.

## Installation

Python3.0 version on linux Os

    There is no external library is required
    
    - sudo python3 packet_sniffer.py 

     
