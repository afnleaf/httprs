/*
 * raw_socket.c
 * Ethernet + ARP + IPv4 + ICMP + UDP + TCP parsing
 * 
 * Compile: gcc -o raw_socket raw_socket.c
 * Run:     sudo ./raw_socket
 * written by Claude to use as a reference for the libc API
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 65536

/* EtherTypes */
#define ETHERTYPE_IPV4  0x0800
#define ETHERTYPE_ARP   0x0806
#define ETHERTYPE_IPV6  0x86DD

/* IP protocols */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17

/* ICMP types */
#define ICMP_ECHO_REPLY         0
#define ICMP_DEST_UNREACHABLE   3
#define ICMP_ECHO_REQUEST       8
#define ICMP_TIME_EXCEEDED      11

/* Well-known ports */
#define PORT_FTP_DATA   20
#define PORT_FTP        21
#define PORT_SSH        22
#define PORT_TELNET     23
#define PORT_SMTP       25
#define PORT_DNS        53
#define PORT_HTTP       80
#define PORT_POP3       110
#define PORT_IMAP       143
#define PORT_HTTPS      443
#define PORT_SMTPS      465
#define PORT_IMAPS      993
#define PORT_POP3S      995

/* TCP flags */
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

struct ipv4_header {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint16_t flags_fragoff;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dest_ip;
} __attribute__((packed));

struct icmp_header {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequence;
} __attribute__((packed));

struct udp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum;
} __attribute__((packed));

/*
 * TCP header - 20 bytes minimum
 * 
 * Data Offset: Number of 32-bit words in TCP header (min 5 = 20 bytes)
 * Flags: Control bits that define packet purpose
 * Window: Flow control - how much data sender can transmit
 * 
 * The flags tell the story:
 *   SYN        - "Let's start a connection"
 *   SYN+ACK    - "OK, let's do it"  
 *   ACK        - "Got it"
 *   PSH+ACK    - "Here's data, process it now"
 *   FIN+ACK    - "I'm done sending"
 *   RST        - "Something's wrong, abort!"
 */
struct tcp_header {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;       /* Sequence number */
    uint32_t ack_num;       /* Acknowledgment number (if ACK set) */
    uint8_t  data_off;      /* Data offset (high 4 bits) + reserved */
    uint8_t  flags;         /* Control flags */
    uint16_t window;        /* Flow control window size */
    uint16_t checksum;
    uint16_t urgent_ptr;    /* Urgent pointer (if URG set) */
    /* Options may follow if data_off > 5 */
} __attribute__((packed));

#define TCP_DATA_OFF(tcp)    (((tcp)->data_off >> 4) & 0x0F)
#define TCP_HEADER_LEN(tcp)  (TCP_DATA_OFF(tcp) * 4)

#define IPV4_VERSION(ip)       (((ip)->version_ihl >> 4) & 0x0F)
#define IPV4_IHL(ip)           ((ip)->version_ihl & 0x0F)
#define IPV4_HEADER_LEN(ip)    (IPV4_IHL(ip) * 4)

void print_ip32(uint32_t ip) {
    unsigned char *bytes = (unsigned char *)&ip;
    printf("%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);
}

const char *ip_protocol_str(uint8_t protocol) {
    switch (protocol) {
        case IP_PROTO_ICMP: return "ICMP";
        case IP_PROTO_TCP:  return "TCP";
        case IP_PROTO_UDP:  return "UDP";
        default:            return "Unknown";
    }
}

const char *icmp_type_str(uint8_t type) {
    switch (type) {
        case ICMP_ECHO_REPLY:       return "Echo Reply";
        case ICMP_DEST_UNREACHABLE: return "Destination Unreachable";
        case ICMP_ECHO_REQUEST:     return "Echo Request";
        case ICMP_TIME_EXCEEDED:    return "Time Exceeded";
        default:                    return "Unknown";
    }
}

const char *port_str(uint16_t port) {
    switch (port) {
        case PORT_FTP_DATA: return "FTP-DATA";
        case PORT_FTP:      return "FTP";
        case PORT_SSH:      return "SSH";
        case PORT_TELNET:   return "Telnet";
        case PORT_SMTP:     return "SMTP";
        case PORT_DNS:      return "DNS";
        case PORT_HTTP:     return "HTTP";
        case PORT_POP3:     return "POP3";
        case PORT_IMAP:     return "IMAP";
        case PORT_HTTPS:    return "HTTPS";
        case PORT_SMTPS:    return "SMTPS";
        case PORT_IMAPS:    return "IMAPS";
        case PORT_POP3S:    return "POP3S";
        default:            return NULL;
    }
}

void print_port(uint16_t port) {
    const char *name = port_str(port);
    if (name) {
        printf("%d (%s)", port, name);
    } else {
        printf("%d", port);
    }
}

/* Build TCP flags string */
void flags_str(uint8_t flags, char *buf) {
    buf[0] = '\0';
    
    if (flags & TCP_SYN) strcat(buf, "SYN ");
    if (flags & TCP_ACK) strcat(buf, "ACK ");
    if (flags & TCP_FIN) strcat(buf, "FIN ");
    if (flags & TCP_RST) strcat(buf, "RST ");
    if (flags & TCP_PSH) strcat(buf, "PSH ");
    if (flags & TCP_URG) strcat(buf, "URG ");
    if (flags & TCP_ECE) strcat(buf, "ECE ");
    if (flags & TCP_CWR) strcat(buf, "CWR ");
    
    /* Remove trailing space */
    int len = strlen(buf);
    if (len > 0) buf[len - 1] = '\0';
}

/* Describe what this packet is doing */
const char *tcp_state_str(uint8_t flags) {
    if ((flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK)) {
        return "Connection accepted (handshake 2/3)";
    }
    if (flags & TCP_SYN) {
        return "Connection request (handshake 1/3)";
    }
    if ((flags & (TCP_FIN | TCP_ACK)) == (TCP_FIN | TCP_ACK)) {
        return "Connection closing";
    }
    if (flags & TCP_FIN) {
        return "Connection close request";
    }
    if (flags & TCP_RST) {
        return "Connection reset (aborted)";
    }
    if ((flags & (TCP_PSH | TCP_ACK)) == (TCP_PSH | TCP_ACK)) {
        return "Data (push)";
    }
    if (flags & TCP_ACK) {
        return "Acknowledgment";
    }
    return "Unknown";
}

void print_hex_dump(unsigned char *data, int len, int max) {
    for (int i = 0; i < len && i < max; i++) {
        printf("%02x ", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < len && i + 1 < max) {
            printf("\n      ");
        }
    }
    if (len > max) printf("... (+%d)", len - max);
}

void print_ascii_dump(unsigned char *data, int len, int max) {
    printf("\"");
    for (int i = 0; i < len && i < max; i++) {
        if (isprint(data[i])) {
            putchar(data[i]);
        } else if (data[i] == '\n') {
            printf("\\n");
        } else if (data[i] == '\r') {
            printf("\\r");
        } else if (data[i] == '\t') {
            printf("\\t");
        } else {
            printf(".");
        }
    }
    if (len > max) printf("...");
    printf("\"");
}

void parse_icmp(unsigned char *payload, int len) {
    if (len < sizeof(struct icmp_header)) return;
    
    struct icmp_header *icmp = (struct icmp_header *)payload;
    
    printf("    ┌─ ICMP ─────────────────────────────────────┐\n");
    printf("    │ Type: %d (%s)\n", icmp->type, icmp_type_str(icmp->type));
    printf("    │ Code: %d\n", icmp->code);
    
    if (icmp->type == ICMP_ECHO_REQUEST || icmp->type == ICMP_ECHO_REPLY) {
        printf("    │ ID: %d   Seq: %d\n", 
               ntohs(icmp->identifier), ntohs(icmp->sequence));
    }
    printf("    └────────────────────────────────────────────┘\n");
}

void parse_dns(unsigned char *data, int len) {
    if (len < 12) return;
    
    uint16_t id = (data[0] << 8) | data[1];
    uint16_t flags = (data[2] << 8) | data[3];
    uint16_t qr = (flags >> 15) & 0x01;
    uint16_t qdcount = (data[4] << 8) | data[5];
    uint16_t ancount = (data[6] << 8) | data[7];
    
    printf("      ┌─ DNS %s ──────────────────────────────┐\n",
           qr ? "RESPONSE" : "QUERY");
    printf("      │ ID: 0x%04x   Questions: %d   Answers: %d\n",
           id, qdcount, ancount);
    
    if (qdcount > 0 && len > 12) {
        printf("      │ Query: ");
        unsigned char *ptr = data + 12;
        int remaining = len - 12;
        
        while (remaining > 0 && *ptr != 0) {
            int label_len = *ptr++;
            remaining--;
            
            if (label_len > remaining) break;
            
            for (int i = 0; i < label_len && remaining > 0; i++) {
                putchar(*ptr++);
                remaining--;
            }
            
            if (*ptr != 0) putchar('.');
        }
        printf("\n");
    }
    
    printf("      └─────────────────────────────────────────────┘\n");
}

void parse_udp(unsigned char *payload, int len, struct ipv4_header *ip) {
    if (len < sizeof(struct udp_header)) return;
    
    struct udp_header *udp = (struct udp_header *)payload;
    
    uint16_t src_port = ntohs(udp->src_port);
    uint16_t dest_port = ntohs(udp->dest_port);
    uint16_t udp_len = ntohs(udp->length);
    
    int data_len = udp_len - sizeof(struct udp_header);
    unsigned char *data = payload + sizeof(struct udp_header);
    
    printf("    ┌─ UDP ──────────────────────────────────────┐\n");
    printf("    │ Src Port:  ");
    print_port(src_port);
    printf("\n");
    printf("    │ Dest Port: ");
    print_port(dest_port);
    printf("\n");
    printf("    │ Length: %d bytes\n", udp_len);
    printf("    └────────────────────────────────────────────┘\n");
    
    if (src_port == PORT_DNS || dest_port == PORT_DNS) {
        parse_dns(data, data_len);
    }
}

void parse_tcp(unsigned char *payload, int len, struct ipv4_header *ip) {
    if (len < sizeof(struct tcp_header)) {
        printf("    [TCP too short: %d bytes]\n", len);
        return;
    }
    
    struct tcp_header *tcp = (struct tcp_header *)payload;
    
    uint16_t src_port = ntohs(tcp->src_port);
    uint16_t dest_port = ntohs(tcp->dest_port);
    uint32_t seq = ntohl(tcp->seq_num);
    uint32_t ack = ntohl(tcp->ack_num);
    uint8_t header_len = TCP_HEADER_LEN(tcp);
    uint8_t flags = tcp->flags;
    uint16_t window = ntohs(tcp->window);
    
    int data_len = len - header_len;
    unsigned char *data = payload + header_len;
    
    char flags_buf[64];
    flags_str(flags, flags_buf);
    
    printf("    ┌─ TCP ──────────────────────────────────────┐\n");
    printf("    │ Src Port:  ");
    print_port(src_port);
    printf("\n");
    printf("    │ Dest Port: ");
    print_port(dest_port);
    printf("\n");
    printf("    │──────────────────────────────────────────────\n");
    printf("    │ Seq: %u\n", seq);
    printf("    │ Ack: %u\n", ack);
    printf("    │──────────────────────────────────────────────\n");
    printf("    │ Flags: [%s]\n", flags_buf);
    printf("    │ → %s\n", tcp_state_str(flags));
    printf("    │──────────────────────────────────────────────\n");
    printf("    │ Window: %u    Header: %d bytes\n", window, header_len);
    printf("    │ Data: %d bytes\n", data_len > 0 ? data_len : 0);
    printf("    └────────────────────────────────────────────┘\n");
    
    /* Show payload if present */
    if (data_len > 0) {
        printf("      Payload:\n");
        printf("      ");
        print_hex_dump(data, data_len, 48);
        printf("\n");
        
        /* Check if it looks like HTTP */
        if (data_len > 4) {
            if (memcmp(data, "GET ", 4) == 0 ||
                memcmp(data, "POST", 4) == 0 ||
                memcmp(data, "HTTP", 4) == 0 ||
                memcmp(data, "HEAD", 4) == 0 ||
                memcmp(data, "PUT ", 4) == 0) {
                printf("      ASCII: ");
                print_ascii_dump(data, data_len, 128);
                printf("\n");
            }
        }
    }
}

void parse_ipv4(unsigned char *payload, int len) {
    if (len < 20) return;
    
    struct ipv4_header *ip = (struct ipv4_header *)payload;
    
    uint8_t version = IPV4_VERSION(ip);
    uint8_t header_len = IPV4_HEADER_LEN(ip);
    uint16_t total_len = ntohs(ip->total_length);
    uint8_t ttl = ip->ttl;
    uint8_t protocol = ip->protocol;
    
    if (version != 4) return;
    
    printf("  ┌─ IPv4 ──────────────────────────────────────┐\n");
    printf("  │ ");
    print_ip32(ip->src_ip);
    printf(" -> ");
    print_ip32(ip->dest_ip);
    printf("\n");
    printf("  │ TTL: %d    Protocol: %s    Len: %d\n", 
           ttl, ip_protocol_str(protocol), total_len);
    printf("  └─────────────────────────────────────────────┘\n");
    
    unsigned char *ip_payload = payload + header_len;
    int ip_payload_len = total_len - header_len;
    
    if (ip_payload_len > 0 && ip_payload_len <= (len - header_len)) {
        switch (protocol) {
            case IP_PROTO_ICMP:
                parse_icmp(ip_payload, ip_payload_len);
                break;
            case IP_PROTO_UDP:
                parse_udp(ip_payload, ip_payload_len, ip);
                break;
            case IP_PROTO_TCP:
                parse_tcp(ip_payload, ip_payload_len, ip);
                break;
        }
    }
}

int main(int argc, char *argv[]) {
    int sockfd;
    unsigned char buffer[BUFFER_SIZE];
    ssize_t numbytes;
    
    /* Filters */
    int filter_tcp = 0;
    int filter_udp = 0;
    int filter_icmp = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--tcp") == 0) filter_tcp = 1;
        if (strcmp(argv[i], "--udp") == 0) filter_udp = 1;
        if (strcmp(argv[i], "--icmp") == 0) filter_icmp = 1;
    }
    
    /* Default to TCP only for cleaner output */
    if (!filter_tcp && !filter_udp && !filter_icmp) {
        filter_tcp = 1;
    }
    
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    
    if (sockfd < 0) {
        perror("socket() failed - are you root?");
        exit(1);
    }
    
    printf("═══════════════════════════════════════════════════════\n");
    printf("  TCP/IP Packet Sniffer\n");
    printf("═══════════════════════════════════════════════════════\n");
    printf("Filters: %s%s%s\n",
           filter_tcp ? "TCP " : "",
           filter_udp ? "UDP " : "",
           filter_icmp ? "ICMP " : "");
    printf("\nTry:\n");
    printf("  curl http://example.com   (HTTP/TCP)\n");
    printf("  curl https://example.com  (HTTPS/TCP - encrypted)\n");
    printf("\n");
    
    int packet_count = 0;
    
    while (1) {
        numbytes = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, NULL, NULL);
        
        if (numbytes < 14) continue;
        
        struct ethhdr *eth = (struct ethhdr *)buffer;
        uint16_t ethertype = ntohs(eth->h_proto);
        
        if (ethertype != ETHERTYPE_IPV4) continue;
        
        unsigned char *payload = buffer + 14;
        int payload_len = numbytes - 14;
        
        struct ipv4_header *ip = (struct ipv4_header *)payload;
        
        /* Apply filters */
        if (ip->protocol == IP_PROTO_TCP && !filter_tcp) continue;
        if (ip->protocol == IP_PROTO_UDP && !filter_udp) continue;
        if (ip->protocol == IP_PROTO_ICMP && !filter_icmp) continue;
        if (ip->protocol != IP_PROTO_TCP && 
            ip->protocol != IP_PROTO_UDP && 
            ip->protocol != IP_PROTO_ICMP) continue;
        
        packet_count++;
        
        printf("════════════════════════════════════════════════════════\n");
        printf("Packet #%d (%zd bytes)\n", packet_count, numbytes);
        printf("────────────────────────────────────────────────────────\n");
        
        parse_ipv4(payload, payload_len);
        
        printf("\n");
    }
    
    close(sockfd);
    return 0;
}
