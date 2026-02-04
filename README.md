# http in c/rust

This repo is playing around with raw sockets right now. Eventually we will build our own http methods. 

## links
https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Methods

https://httpwg.org/specs/rfc9110.html

https://en.wikipedia.org/wiki/HTTP

## plan
goal is to make some get and post request working.

there are many other methods but they are not as important.

the error codes are quite important.

this is good arena memory allocation strategy.

should we do it in C or Rust? Well personally I would find more use in my own Rust

Raw Sockets
ARP
IPv4
ICMP
UDP
DNS
TCP
HTTP

## how it works?

So there is a client (user agent) and a server. Do we need to go back down to TCP/UDP level?: Yes this is essential. Look at the internet as layers of different technologies, which we can peel back like an onion. This is called the OSI Model 

https://en.wikipedia.org/wiki/OSI_model

Standards and Laws (Platonic forms of the internet?)
|
v
Physical Links (Ethernet, Wifi) 
|
v
Mac Address
|
v
Internet (ipv4, ipv6, icmp) -> (ARP, NDP)
|
v
Transportation (TCP, UDP) -> (DNS) -> (TLS, DTLS)
|
v
Apps (HTTP, POP, SMTP, IMAP, GOPHER, LDAP, NTP, DHCP, RTSP) <-- we are here
|
v
More Apps (WWW, WebAPI, Database, Email)
|
v
Primitives (Files, Data, Text, Contact Info, Video Streaming, etc)
|
v
Local compute (decompression, decoding, presentation)

If we want to build applications on top of HTTP, like WebAPIs and Databases, then we need to understand everything under it. 

### Physical + Link Layer

Ethernet and Wifi are physical implementation of the network. these technologies move bits. voltage on copper, light pulses through fiber, radio waves and frequency modulations for wifi. What they deliver are frames, our first real data strucutre.

| Preamble | SFD | Dest MAC | Src MAC | EtherType | Payload | FCS |
| 7 bytes  | 1   | 6 bytes  | 6 bytes | 2 bytes   | 46-1500 | 4   |

The first 8 bytes seem to get handled by hardware? The mac addresses are like physical device identifiers? Interestingly the payload is quite small. There is a thing called a CRC or FCS depending on the type of frame that are also handled by the hardware (network interface controller). 

- https://en.wikipedia.org/wiki/MAC_address
- https://en.wikipedia.org/wiki/Address_Resolution_Protocol
- https://www.rfc-editor.org/rfc/rfc826

ARP helps link MAC and IP addresses?

Wikipedia:
>Two computers X and Y are connected on LAN. X is trying to find an IP which belongs in this case to Y. First, X broadcasts an ARP request message with a MAC address attached and it requests a response from the target IP. All nodes on the network receive the message but only Y replies because it has the target IP. So Y responds with an ARP message containing its own MAC addresses. Then the packet can be sent from X to Y.  

You're basically discovering the mac address of an IP and then caching that info so that you can send ip packets. Arp lets you build the ethernet frame by telling you the destination MAC address. But this is all local network, your router will handle when you want to connect to the wider internet and of course DNS does a lot. The IP stuff goes into the payload of an ethernet frame.

### Internet Layer

- https://www.rfc-editor.org/rfc/rfc791
- https://en.wikipedia.org/wiki/Internet_Protocol
- https://en.wikipedia.org/wiki/IPv4
- https://en.wikipedia.org/wiki/IPv6

IP addresses. This is where packets come into play.

There is a header and a body.

### Transportation

UDP

https://www.rfc-editor.org/rfc/rfc768

TCP

https://en.wikipedia.org/wiki/Transmission_Control_Protocol

## Sockets

https://en.wikipedia.org/wiki/Network_socket

https://en.wikipedia.org/wiki/Berkeley_sockets

Maybe not safe to implement raw sockets in production code.

