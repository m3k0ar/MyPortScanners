#include <stdio.h>
#include <memory.h>
#include <stdint.h>
#include <pcap.h>


struct IPHeader {
    // src ip
    // dest ip
    // version
    //    __u8 	tos
    //    __u16 	tot_len
    //    __u16 	id
    //    __u16 	frag_off
    //    __u8 	ttl
    //    __u8 	protocol
    //    __u16 	check
    //    __u32 	saddr
    //    __u32 	daddr
};

struct TCPHeader {
    uint16_t src_port;  /* source port */
    uint16_t dst_port;  /* destination port */
    uint32_t seq;   /* sequence number */
    uint32_t ack;   /* acknowledgement number */

#if BYTE_ORDER == LITTLE_ENDIAN
    u_int th_x2:4,  /* (unused) */
        th_off:4;  /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int th_off:4,  /* data offset */
        th_x2:4;  /* (unused) */
#endif
    u_char flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)

    u_short win;   /* window */
    u_short sum;   /* checksum */
    u_short urp;   /* urgent pointer */
};

void printUsage() 
{
    printf("Usage:\n");
    printf("  synscan <host> <port> <interface>\n");
    printf("Examples usage:\n");
    printf("  synscan Armands-MBP 22 en0\n");
    printf("  synscan 8.8.8.8 53 en1\n");
}

void sendSYNPacket(pcap_t * handle, const char* host, char* port)
{
    printf("Sending SYN packet to %s:%s\n", host, port);
    struct TCPHeader outPacket;
    // Set all flags on the tcp packet
    outPacket.ack = 0;
    outPacket.seq = 0;
    outPacket.flags = 2;    // SYN only set
    // TODO combine the IP header + TCP header
    // TODO Set other properties, like checksum?
    // pcap_t *, const u_char *, int
    pcap_sendpacket(handle, (const u_char *)&outPacket, sizeof (outPacket));
}

/*
* listener
* we set up a packet and listen specifically to SYN packet coming from the host
* once a packet is captured, we send a syn packet (which will be created using the TCPHeader struct) with sendSYNPacket()
*
*/
void SYNScan(const char* host, char* port, char* interface)
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    // pcap_open_live(interface, buffer_size, packet_count_limit, timeout_limit, error_buffer)
    // open device for live capture
    pcap_t* handle = pcap_open_live(
        interface,
        4096,
        10000,
        3000,
        error_buffer);
    printf("Opened device %s for reading.\n", interface);

    {   // TODO do this capturing in a separate thread

        // set filter
        struct bpf_program filter;
        const char* filter_string = "tcp[13] = 18 and src host "; // syn-ack; // TODO ANd? sequence 0 and ack number 1? and dst port will equal original src port
        char* filterString [strlen(filter_string) + strlen(host) + 1];
        strcpy(filterString, filter_string);
        strcat(filterString, host);
        bpf_u_int32 ip = 0;
        // pcap_t *, struct bpf_program *, const char *, int, bpf_u_int32
        pcap_compile(handle, &filter, filter_string, 0, ip);
        pcap_setfilter(handle, &filter);
        printf("Set filter: %s\n", filter_string);


        // attempt to capture one packet
        // pcap_t *, struct pcap_pkthdr *
        struct pcap_pkthdr packetHeader;
        const u_char* packet = pcap_next(handle, &packetHeader);
        if(packet == NULL)
        {
            printf("No packet found\n");
            // return 2;
        }
        printf("Captured packet header length: %d\n", packetHeader.caplen);

        // TODO Lock and update the mutual object and signal done
    }

    // send syn packet
    sendSYNPacket(handle, host, port);

    // TODO While the mutual object is not updated with a response & timeout not reached
        // TODO checking the mutual object// wait for lock?
        // TODO If it did receive synack then send reset
}

int main(int argc, char** argv)
{
    // If not enough arguments provided, printusage and quit
    if (argc < 4) {
        printf("Not enough arguments provided.\n");
        printUsage();
        return 1;
    }

    const char* host = argv[1];
    char* port = argv[2];
    char* interface = argv[3];
    printf("Scanning %s:%s using interface %s.\n", host, port, interface);

    // scanning
    SYNScan("Armands-MBP", "22", "en0");
}

