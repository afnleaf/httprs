// src/main.rs
#![allow(dead_code, unused)]

// standard
use std::io;
use std::mem;
use std::ptr;
// libc
use libc::{
    // Socket creation
    socket,
    htons,
    bind,
    close,
    setsockopt,
    
    // Socket types and families
    AF_PACKET,
    SOCK_RAW,
    SOL_SOCKET,
    SO_BINDTODEVICE,
    
    // Sending/receiving
    recvfrom,
    sendto,
    sockaddr,
    socklen_t,
    
    // For interface binding
    sockaddr_ll,
    c_void,
    c_int,
    c_char,
    ssize_t,
};

// Network byte order: 0x0003 -> big endian
const ETH_P_ALL:    u16 = 0x0003;
const ETH_P_IP:     u16 = 0x0800;
const ETH_P_ARP:    u16 = 0x0806;

// IP protocols
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_TCP:  u8 = 6;
const IPPROTO_UDP:  u8 = 17;

// Buffer size
const BUFFER_SIZE:  usize = 65536;

// Pretty print MAC addresses
fn format_mac(mac: &[u8]) -> String {
    format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

// Ethertype to string
fn ethertype_str(ethertype: u16) -> &'static str {
    match ethertype {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        _ => "Unknown",
    }
}

fn protocol_str(protocol: u8) -> &'static str {
    match protocol {
        IPPROTO_ICMP => "ICMP",
        IPPROTO_TCP => "TCP",
        IPPROTO_UDP => "UDP",
        _ => "Unknown",
    }
}

struct EthernetFrame<'a> {
    dest_mac:       [u8; 6], 
    src_mac:        [u8; 6],
    ethertype:      u16,
    payload:        &'a [u8],
}

// takes in a raw ethernet buffer and returns the header and the payload
fn parse_ethernet_frame<'a> ( 
    numbytes: isize, 
    frame_buf: &'a [u8]
) -> EthernetFrame<'a> {
    let dest_mac = frame_buf[0..6]
        .try_into()
        .unwrap_or_else(|e| {
            eprintln!("Failed to parse mac address, not 6 bytes {e}");
            std::process::exit(1);
        });
    let src_mac = frame_buf[6..12]
        .try_into()
        .unwrap_or_else(|e| {
            eprintln!("Failed to parse mac address, not 6 bytes {e}");
            std::process::exit(1);
        });
    let ethertype = u16::from_be_bytes([frame_buf[12], frame_buf[13]]);
    let payload = &frame_buf[14..numbytes as usize];

    EthernetFrame {
        dest_mac,
        src_mac,
        ethertype,
        payload,  
    }
}

fn format_ethernet_frame(ef: &EthernetFrame) -> String {
    format!("\
        destination mac address: {}\n\
        source mac address: {}\n\
        ethertype: 0x{:04x} ({})\n\
        ----------------------------------------------------------\
        ",
        format_mac(&ef.dest_mac),
        format_mac(&ef.src_mac),
        ef.ethertype, 
        ethertype_str(ef.ethertype),
        //{:X?}...\n\
        //ef.payload,
    )
}

struct Ipv4<'a> {
    header:     Ipv4Header,
    payload:    &'a [u8],
}

#[derive(Debug)]
struct Ipv4Header {
    version:     u8,
    ihl:         u8,
    tos:         u8,
    total_len:   u16,
    id:          u16,
    flags:       u8,
    frag_offset: u16, 
    ttl:         u8,
    protocol:    u8,
    checksum:    u16,
    src_ip:      [u8; 4],
    dest_ip:     [u8; 4],
}

// p for payload
// parse the header out and the payload
fn parse_ipv4<'a>(p: &'a [u8]) -> Ipv4<'a> {
    // first byte, first 4 bits, right shift 
    // 0b01234567 big endian for network
    // 0bXXXX0123 ?
    let version = p[0] >> 4;
    // mask to grab bottom 4
    // 0x0F 0b00001111
    let ihl = p[0] & 0x0F;
    let tos = p[1];
    let total_len = u16::from_be_bytes([p[2], p[3]]);
    let id = u16::from_be_bytes([p[4], p[5]]);
    // shift 5 right get 3
    let flags = p[6] >> 5;
    let frag_offset = u16::from_be_bytes([
        p[6] & 0x1F,
        p[7]
    ]);
    let ttl = p[8];
    let protocol = p[9];
    let checksum = u16::from_be_bytes([p[10], p[11]]);
    // should this just be a u32?
    //let src_ip = u32::from_be_bytes([p[12], p[13], p[14], p[15]]);
    //let dest_ip = u32::from_be_bytes([p[16], p[17], p[18], p[19]]);
    let src_ip = [p[12], p[13], p[14], p[15]];
    let dest_ip = [p[16], p[17], p[18], p[19]];

    let header = Ipv4Header {
        version,
        ihl,
        tos, 
        total_len,
        id,
        flags,
        frag_offset,
        ttl,
        protocol,
        checksum,
        src_ip,
        dest_ip,
    };

    //println!("{:#?}", header);

    // ok
    let header_len = (ihl * 4) as usize;
    let ip_payload_len = total_len as usize - header_len;
    let payload = &p[header_len..(header_len + ip_payload_len)];

    Ipv4 {
        header,
        payload,
    }
}

fn format_ip(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

fn format_ipv4(ip: Ipv4) -> String {
    format!("\
        Ipv4\n\
        version: {}\n\
        internet header length (ihl): {}\n\
        type of service (tos): {}\n\
        total length: {}\n\
        id: {}\n\
        flags: {}\n\
        frag offset: {}\n\
        time to live (ttl): {}\n\
        protocol: {} ({})\n\
        checksum: {}\n\
        source ip: {}\n\
        destination ip: {}\n\
        payload: {:X?}\n\
        ----------------------------------------------------------\
        ",
        ip.header.version,
        ip.header.ihl,
        ip.header.tos, 
        ip.header.total_len,
        ip.header.id,
        ip.header.flags,
        ip.header.frag_offset,
        ip.header.ttl,
        ip.header.protocol,
        protocol_str(ip.header.protocol),
        ip.header.checksum,
        format_ip(ip.header.src_ip),
        format_ip(ip.header.dest_ip),
        ip.payload,
    )
}

fn main() {
    println!("Raw socket in Rust");
    
    // You'll build everything from here
    // 
    // 1. Create raw socket
    // 2. Receive frames into a buffer
    // 3. Parse ethernet header (bytes 0-13)
    // 4. Parse IP header (bytes 14+)
    // 5. Parse TCP/UDP/ICMP (bytes 14 + ip_header_len +)
    
    let sockfd: i32;
    let mut frame_buffer: [u8; BUFFER_SIZE];
    let numbytes: isize; // should be set to i32?, pretty sure the max is i16..

    // socket call to libc
    unsafe { sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL).into()); }

    if sockfd < 0 {
        eprintln!("socket() failed - are you root?");
        std::process::exit(1);
    }

    println!("Socket created (fd={}).", sockfd);
    println!("Listening...");
    
    let mut packet_count = 0;
    loop {
        frame_buffer = [0; BUFFER_SIZE];

        let numbytes = unsafe { 
            // recvfrom call to libc
            // his libc? whack
            recvfrom(
                sockfd, 
                frame_buffer.as_mut_ptr() as *mut c_void, // his voids? whack
                BUFFER_SIZE, 
                0, 
                ptr::null_mut(), // his nulls? whack
                ptr::null_mut(),
            )
        };
        
        // skip if there is no ethernet frame header
        if numbytes < 14 { continue; }

        // parse ethernet frame into header and payload
        let ef = parse_ethernet_frame(numbytes, &frame_buffer);

        println!("==========================================================");
        println!("packet #: {}", packet_count);
        println!("numbytes: {}", numbytes);
        println!("{}", format_ethernet_frame(&ef));
        if ef.ethertype == ETH_P_IP {
            let ipv4 = parse_ipv4(&ef.payload);
            println!("{}", format_ipv4(ipv4));
        }
        println!("==========================================================");
        println!("\n\n");

        packet_count += 1;
    }

    unsafe { close(sockfd); }
}
