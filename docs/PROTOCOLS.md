# Protocol Primer

This primer explains the protocols used in the simulation, in the order a request encounters them. It is written for students who are learning computer networks for the first time.

## 1. The layered model

Network software is organised in layers. Each layer offers a service to the layer above and uses the service of the layer below.

| Layer (TCP/IP) | Example protocols | Responsibility |
|---|---|---|
| Application | HTTP, TLS, DNS | Meaning of the data |
| Transport | TCP, UDP | Reliable or fast delivery between processes |
| Internet | IP | Addressing and routing between networks |
| Link | Ethernet, Wi-Fi | Delivery on a single physical segment |

The OSI model splits these into seven layers. The TCP/IP model used in practice has four. Each layer adds a header to the data it receives from the layer above. This is called encapsulation, and the receiver removes the headers in reverse order.

## 2. DNS: finding the server

Computers connect to IP addresses, but people use names. The Domain Name System (DNS, RFC 1035) maps names to addresses.

A typical lookup:

1. The application asks the operating system to resolve `example.com`.
2. The operating system checks its cache. If the answer is missing or expired, it sends a query to a configured recursive resolver.
3. The resolver walks the hierarchy (root, top-level domain, authoritative server) if it does not already know the answer.
4. The answer is returned with a time to live (TTL) that controls how long it can be cached.

Key facts for students:

- Classic DNS queries travel in plaintext over UDP port 53 by default. Anyone on the path can read the queried name.
- Encrypted transports exist. DNS over TLS (DoT, RFC 7858) and DNS over HTTPS (DoH, RFC 8484) carry the same queries inside encrypted channels. The name is then hidden from passive observers on the path, but the resolver still sees it.

## 3. TCP: a reliable byte stream

The Transmission Control Protocol (RFC 793) provides ordered, reliable delivery on top of the unreliable packet service of IP.

- **Connection setup (three-way handshake):** the client sends SYN, the server replies SYN-ACK, the client sends ACK. Only then can application data flow.
- **Reliability:** every segment carries a sequence number. The receiver acknowledges data, and the sender retransmits anything not acknowledged in time.
- **Congestion control:** the sender adjusts how much unacknowledged data it keeps in flight, based on loss and delay signals.

In the simulation, packet loss forces retransmissions and therefore increases latency. Very high loss makes the connection fail.

## 4. TLS: encrypted channels

Transport Layer Security (TLS, RFC 8446 for version 1.3) provides confidentiality, integrity and server authentication for application protocols such as HTTP.

The handshake, simplified:

1. The client sends a **ClientHello** message. It lists supported cipher suites, a random value, and extensions.
2. The server answers with its certificate, a key share and a finished message.
3. Both sides derive keys and switch to encrypted records.

Only the ClientHello is sent before the keys exist, so some of its fields are visible to anyone on the path. One of them is the **Server Name Indication (SNI)** extension (RFC 6066, section 3), which carries the host name the client wants. SNI is needed so that a server hosting many sites can choose the right certificate.

Consequence for students: the contents of an HTTPS request are encrypted, but the destination host name is often visible in the ClientHello. This is an important point in privacy and network policy discussions.

Encrypted Client Hello (ECH) is an ongoing standardisation effort that aims to encrypt the ClientHello itself. It is a good topic for further reading.

## 5. Deep Packet Inspection (DPI)

DPI refers to devices that look inside traffic beyond the headers needed for routing. Typical inspection targets include:

- DNS query names (plaintext DNS)
- TLS SNI (visible before encryption starts)
- HTTP host headers (plaintext HTTP only)

A simple inspector is a rule engine: it extracts a field, compares it with a list of names, and applies an action on a match, such as resetting the connection or dropping packets. Real systems are far more complex, but this model captures the main idea: **the more of the protocol stack an observer can read, the more decisions it can make.**

Relevant questions for discussion:

- Which fields are visible at each step of a connection, and why?
- How does encryption change the set of visible fields?
- What are the trade-offs between privacy, network management and user control?

## 6. How the simulation maps to these protocols

| Simulation step | Protocol | What the inspector can see |
|---|---|---|
| DNS query | DNS over UDP (plaintext) or encrypted resolver | Query name, or nothing if encrypted |
| TCP handshake | TCP | Addresses and ports only |
| ClientHello | TLS | SNI, unless it is hidden |
| Application data | TLS records | Sizes and timing only |

The simulation measures how the success rate and timeline change when each visibility point is removed or changed. The purpose is to make the relationship between protocol design and observability concrete.

## 7. Suggested exercises

1. Run the simulation with inspection enabled and disabled. Explain why the outcome changes.
2. Increase the loss rate step by step. Identify the point where retransmissions start to dominate the timeline.
3. Trace one request through the event log and label each event with the protocol layer it belongs to.
4. Read RFC 6066 section 3 and explain why the SNI field exists.
5. Compare DoT and DoH. Which observers can still see the query name in each case?

## Further reading

- Kurose and Ross, *Computer Networking: A Top-Down Approach*
- RFC 791, RFC 793, RFC 1035, RFC 6066, RFC 8446, RFC 7858, RFC 8484
- Internet Engineering Task Force working group pages on TLS and DNS privacy
