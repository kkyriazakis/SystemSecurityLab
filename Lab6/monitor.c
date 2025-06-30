#define _GNU_SOURCE
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h> /* if this gives you an error try pcap/pcap.h */
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h> //Provides declarations for udp header
#include <netinet/tcp.h> //Provides declarations for tcp header
#include <netinet/ip.h>  //Provides declarations for ip header


#define PACKETS_TO_CAPTURE 10

int Net_flows = 0;
int TCP_flows = 0;
int UDP_flows = 0;
int tot_packets = 0;
int TCP_recieve = 0;
int UDP_recieve = 0;
int TCP_bytes = 0;
int UDP_bytes = 0;
char localIP[20];

void usage(void) {
	printf( "\n"
			"usage:\n"
			"\t./assign_6\n"
			"Options:\n"
			"-i <Device to capture>, Network interface name (e.g., eth0)\n"
			"-r <input file>, Packet capture file name (e.g., test.pcap)\n"
			"-h, Help message\n\n"
			);
	exit(1);
}

void printStats(){
    printf("\n\n======= Packet Statistics =======\n");
    printf("Total Flows captured     : %d\n", Net_flows);
    printf("Total TCP Flows captured : %d\n", TCP_flows);
    printf("Total UDP Flows captured : %d\n", UDP_flows);
    printf("Total packets captured   : %d\n", tot_packets);
    printf("TCP packets recieved     : %d\n", TCP_recieve);
    printf("UDP packets recieved     : %d\n", UDP_recieve);
    printf("TCP bytes recieved       : %d\n", TCP_bytes);
    printf("UDP bytes recieved       : %d\n", UDP_bytes);
    printf("\n=================================\n");
}



void PrintData (const u_char * data , int Size) {
    int i;
    for(i=0; i<Size; i++) {
        printf(" %02X",(unsigned int)data[i]);
    }
    printf("\n\n");
}



void decode_tcp_packet(const u_char * Buffer, int Size)
{
    unsigned short iphdrlen;
    struct sockaddr_in source,dest;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));            
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    //Is the packet ingoing?
    if( strcmp(inet_ntoa(dest.sin_addr), localIP) == 0 ){
        TCP_recieve++;
        TCP_bytes += ntohs(iph->tot_len) - (unsigned int)tcph->doff*4;
    }


    printf("\n\n===== TCP Packet =====\n");  
    printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );
    printf("   |-Source Port      : %u\n", ntohs(tcph->source));

    printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    printf("   |-Destination Port : %u\n", ntohs(tcph->dest));

    printf("   |-Header Length    : %d BYTES\n" ,(unsigned int)tcph->doff*4);
    printf("   |-Payload Length   : %d BYTES\n", ntohs(iph->tot_len) - (unsigned int)tcph->doff*4);
     
    printf("\nData Payload\n");    
    PrintData(Buffer + header_size , Size - header_size );
                        
    printf("======================\n");

}


void decode_udp_packet(const u_char *Buffer , int Size) {    
    unsigned short iphdrlen;
    struct sockaddr_in source,dest;
    
    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;
    
    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    //Is the packet ingoing?
    if( strcmp(inet_ntoa(dest.sin_addr), localIP) == 0 ){
        UDP_recieve++;
        UDP_bytes += ntohs(iph->tot_len) - 2;
    }
    
    printf("\n\n===== UDP Packet =====\n");
    printf("   |-Source IP        : %s\n" , inet_ntoa(source.sin_addr) );   
    printf("   |-Source Port      : %d\n" , ntohs(udph->source));

    printf("   |-Destination IP   : %s\n" , inet_ntoa(dest.sin_addr) );
    printf("   |-Destination Port : %d\n" , ntohs(udph->dest));

    printf("   |-Header Length    : 2 BYTES\n");
    printf("   |-Payload Length   : %d BYTES\n", ntohs(iph->tot_len) - 2); //////////////////////////////
     
    printf("\nData Payload\n");
    PrintData(Buffer + header_size , Size - header_size);
    
    printf("======================\n");
}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer) {
    int size = header->len;
    tot_packets++;
    Net_flows++;

    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {       
        case 6:  //TCP Protocol
            TCP_flows++;            
            decode_tcp_packet(buffer , size);
            break;
        
        case 17: //UDP Protocol
            UDP_flows++;
            decode_udp_packet(buffer , size);
            break;
    }
}

void network_monitor(char *dev){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    descr = pcap_open_live(dev,BUFSIZ,0,1000,errbuf);

    if(descr == NULL){
        printf("pcap_open_live(): %s\n",errbuf);
        exit(1);
    }

    //Find local IP address
    pcap_if_t *alldevs;
    char* tmp;
    pcap_findalldevs(&alldevs, errbuf);
    for(pcap_if_t *d=alldevs; d!=NULL; d=d->next) {
        for(pcap_addr_t *a=d->addresses; a!=NULL; a=a->next) {
            if(a->addr->sa_family == AF_INET && strcmp(dev, d->name) == 0){
                tmp = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
                strcpy(localIP, tmp);
                break;
            }
        }
    }
    pcap_freealldevs(alldevs);

    
    //Put the device in sniff loop
    pcap_loop(descr, PACKETS_TO_CAPTURE, process_packet, NULL);

    printStats();
}


void network_monitor_offline(char *filename){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;

    if (!(descr = pcap_open_offline(filename, errbuf))) {
        printf("Error in opening savefile, %s, for reading: %s\n", filename, errbuf);
        return;
    }

    if (pcap_dispatch(descr, 0, &process_packet, (u_char *)0) < 0) {
        exit(-1);
    }
    printStats();
}


int main(int argc, char *argv[]) {
	int ch;
    
	
	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "i:r:")) != -1) {
		switch (ch) {		
		case 'i':
            //My default Device: enp5s0
			network_monitor(strdup(optarg));
			break;
		case 'r':
			network_monitor_offline(strdup(optarg));
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	return 0;
}
