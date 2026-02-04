/*
 * raw_socket.c
 *
 * the goal here is to look at raw ethernet frames
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 65536
#define HEADER_SIZE 14

/* 
 * Ethernet frame
 *
 * destination mac address 6 bytes
 * source mac address 6 bytes
 * ethertype 2 bytes
 * payload 46 to 1500 bytes (can we do multiple frames for one large data)
 */

// Ethertype opcodes
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD

// ARP opcodes
#define ARP_REQUEST     1
#define ARP_REPLY       2

// IP protocols
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

// ARP packet structure (for Ethernet + IPv4)
struct arp_packet {
    uint16_t hw_type;        /* Hardware type: 1 = Ethernet */
    uint16_t proto_type;     /* Protocol type: 0x0800 = IPv4 */
    uint8_t  hw_len;         /* Hardware address length: 6 for MAC */
    uint8_t  proto_len;      /* Protocol address length: 4 for IPv4 */
    uint16_t opcode;         /* 1 = request, 2 = reply */
    uint8_t  sender_mac[6];
    uint8_t  sender_ip[4];
    uint8_t  target_mac[6];
    uint8_t  target_ip[4];
} __attribute__((packed));   /* Don't let compiler add padding */

// IPv4 header
struct ipv4_header {
    uint8_t  version_ihl;      /* version << 4 | ihl */
    uint8_t  tos;              /* Type of Service (ignore used for DSCP/ECN) */
    uint16_t total_length;     /* Total packet length (header + payload) */
    uint16_t identification;   /* Used for fragmentation reassembly */
    uint16_t flags_fragoff;    /* 3 bits flags, 13 bits fragment offset */
    uint8_t  ttl;              /* Time To Live - decremented at each hop */
    uint8_t  protocol;         /* What's the payload: 1=ICMP, 6=TCP, 17=UDP */
    uint16_t checksum;         /* Header checksum */
    uint32_t src_ip;           /* Source IP (network byte order) */
    uint32_t dest_ip;          /* Destination IP (network byte order) */
    /* Options may follow if IHL > 5 */
} __attribute__((packed));

// helper macros for version_ihl byte
#define IPV4_VERSION(ip)        (((ip)->version_ihl >> 4) & 0x0F)
#define IPV4_IHL(ip)            ((ip)->version_ihl & 0x0F)
#define IPV4_HEADER_LEN(ip)     (IPV4_IHL(ip) * 4)

// helper macros for flags_fragoff
#define IPV4_FLAGS(ip)          ((ntosh((ip)->flags_fragoff) >> 13) & 0x07)
#define IPV4_FRAGOFF(ip)        (ntohs((ip)->flags_fragoff) & 0x1FFF)

// flag bits
#define IP_FLAG_DF  0x02
#define IP_FLAG_MF  0x01

// helper functions --------------------------------------------------------- /

void print_mac(unsigned char* mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x", 
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

const char* ethertype_str(uint16_t ethertype) {
    switch (ethertype) {
        case ETHERTYPE_IPV4:    return "IPv4";
        case ETHERTYPE_IPV6:    return "IPv6";
        case ETHERTYPE_ARP:     return "ARP";
        default:                return "Unknown";
    }
}

void print_hex_dump(unsigned char* data, int len) {
    printf("  ");
    for (int i = 0; i < len && i < 64; ++i) {
        printf("%02x", data[i]);
        //if (len > 64) printf("... (%d more bytes)", len - 64);
    }
    printf("\n");
}



void print_ip(unsigned char *ip) {
    printf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
}

void parse_arp(unsigned char *payload, int len) {
    if (len < sizeof(struct arp_packet)) {
        printf("  [ARP packet too short: %d bytes]\n", len);
        return;
    }
    
    struct arp_packet *arp = (struct arp_packet *)payload;
    
    /* Verify it's Ethernet + IPv4 ARP */
    uint16_t hw_type = ntohs(arp->hw_type);
    uint16_t proto_type = ntohs(arp->proto_type);
    uint16_t opcode = ntohs(arp->opcode);
    
    if (hw_type != 1 || proto_type != ETHERTYPE_IPV4) {
        printf("  [Non-Ethernet/IPv4 ARP: hw=%d proto=0x%04x]\n", 
               hw_type, proto_type);
        return;
    }
    
    printf("  ┌─ ARP ");
    
    switch (opcode) {
        case ARP_REQUEST:
            printf("REQUEST ─────────────────────────────────┐\n");
            printf("  │ Who has ");
            print_ip(arp->target_ip);
            printf("? Tell ");
            print_ip(arp->sender_ip);
            printf(" (");
            print_mac(arp->sender_mac);
            printf(")\n");
            break;
            
        case ARP_REPLY:
            printf("REPLY ───────────────────────────────────┐\n");
            printf("  │ ");
            print_ip(arp->sender_ip);
            printf(" is at ");
            print_mac(arp->sender_mac);
            printf("\n");
            break;
            
        default:
            printf("UNKNOWN (opcode=%d) ─────────────────────┐\n", opcode);
            break;
    }
    
    printf("  │                                                │\n");
    printf("  │ Sender: ");
    print_mac(arp->sender_mac);
    printf(" -> ");
    print_ip(arp->sender_ip);
    printf("    │\n");
    printf("  │ Target: ");
    print_mac(arp->target_mac);
    printf(" -> ");
    print_ip(arp->target_ip);
    printf("    │\n");
    printf("  └────────────────────────────────────────────────┘\n");
}

int main(int argc, char* argv[]) {
    int sockfd;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t numbytes;

    // create a raw socket
    //
    // AF_PACKET    raw packet access at device driver level
    // SOCK RAW     include link level header
    // ETH_P_ALL    receive all protocols
    //

    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sockfd < 0) {
        perror("socket() failed - are you root?");
        exit(1);
    }

    printf("Raw socket created successfully (fd=%d)\n", sockfd);
    printf("Listening for ethernet frames...\n\n");

    if (argc > 1) {
        struct sockaddr_ll sll;
        struct ifreq ifr;

        memset(&sll, 0, sizeof(sll));
        memset(&ifr, 0, sizeof(ifr));


        strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';

        if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
            perror("ioctl SIOCGIFINDEX");
            close(sockfd);
            exit(1);
        }

        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(ETH_P_ALL);

        if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind");
            close(sockfd);
            exit(1);
        }

        printf("Bound to interface %s (index %d)\n\n",
               argv[1], ifr.ifr_ifindex);
    }

    int frame_count = 0;
    int arp_count = 0;

    while(1) {
        numbytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);

        if (numbytes < 0) {
            perror("recvfrom");
            continue;
        }

        // ethernet header is 14 bytes minimum
        if (numbytes < HEADER_SIZE) {
            printf("Runt frame (%zd bytes)\n", numbytes);
            continue;
        }

        frame_count++;

        // parse ethernet header
        // We can use struct ethhdr from linux/if_ether.h:
        //    struct ethhdr {
        //        unsigned char h_dest[6];    // destination MAC
        //        unsigned char h_source[6];  // source MAC  
        //        __be16 h_proto;             // protocol (big-endian!)
        //    };
        //  
        // Or just index into the buffer directly:
        //  bytes 0-5:   dest MAC
        //  bytes 6-11:  src MAC
        //  bytes 12-13: ethertype (big-endian)

        struct ethhdr *eth = (struct ethhdr*)buffer;
        // how do I bitshift without using ethhdr?

        // Network byte order is big-endian
        // x86 is little-endian
        // ntohs = "network to host short" - swaps bytes if needed
        // 
        // Example: EtherType 0x0800 (IPv4)
        //   On wire (big-endian):    08 00
        //   In memory (little-end):  00 08  <- wrong if we just cast
        //   After ntohs:             08 00  <- correct
        
        uint16_t ethertype = ntohs(eth->h_proto);

        printf("Frame #%d (%zd bytes)\n", frame_count, numbytes);
        printf("\tDest MAC: ");
        print_mac(eth->h_dest);
        printf("\tSrc MAC: ");
        print_mac(eth->h_source);
        printf("\n\tType:\t0x%04x (%s)\n", ethertype, ethertype_str(ethertype));

        unsigned char* payload = buffer + HEADER_SIZE;
        int payload_len = numbytes - HEADER_SIZE;

        printf("\tPayload (%d bytes):\n", payload_len);
        print_hex_dump(payload, payload_len);
        printf("\n");

        if (ethertype == ETHERTYPE_ARP) {
            arp_count++;
            
            printf("═════════════════════════════════════════════════════\n");
            printf("Frame #%d (ARP #%d) - %zd bytes\n"
                   , frame_count, arp_count, numbytes);
            printf("─────────────────────────────────────────────────────\n");
            printf("  Ethernet Header:\n");
            printf("    Dest MAC: ");
            print_mac(eth->h_dest);
            printf("\n    Src MAC:  ");
            print_mac(eth->h_source);
            printf("\n    Type:     0x%04x (%s)\n"
                   , ethertype, ethertype_str(ethertype));
            printf("─────────────────────────────────────────────────────\n");
            
            unsigned char *payload = buffer + 14;
            int payload_len = numbytes - 14;
            
            parse_arp(payload, payload_len);
            
            printf("─────────────────────────────────────────────────────\n");
            printf("  Raw payload:\n");
            print_hex_dump(payload, payload_len);
            printf("═════════════════════════════════════════════════════\n\n");
        }
    }

    close(sockfd);
    return 0;
}
