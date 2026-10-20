# ORWOX Network Simulation

An interactive, discrete-event simulation of how a client host communicates with a remote server across a network that performs Deep Packet Inspection (DPI). It models the DNS lookup, TCP handshake and TLS handshake of a single HTTPS request, shows where an inspecting middlebox can observe traffic, and lets you change link, DNS and inspection parameters to see how the outcome changes.

It is built for teaching and research on computer networks.

- **Live demo:** published with GitHub Pages (see [Publishing the site](#publishing-the-site))
- **Protocol primer for students:** [docs/PROTOCOLS.md](docs/PROTOCOLS.md)
- **Architecture:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Contents

1. [Goals](#goals)
2. [Scope](#scope)
3. [Repository layout](#repository-layout)
4. [Running the simulation](#running-the-simulation)
5. [Simulation model](#simulation-model)
6. [Parameters](#parameters)
7. [Publishing the site](#publishing-the-site)
8. [Testing](#testing)
9. [Limitations and responsible use](#limitations-and-responsible-use)
10. [References](#references)

## Goals

1. Show the layered path of a request: application, transport, network and link layers.
2. Explain how a passive inspector can make decisions from observable metadata such as DNS query names and the TLS Server Name Indication (SNI).
3. Demonstrate how encryption and resolver choice change what an observer can see, using measurable outcomes.

## Scope

| Area | Included | Not included |
|---|---|---|
| Layers | Application (DNS, HTTPS), transport (TCP), link-level delay and loss | Physical signalling |
| Routing | Simplified single path with ISP and server nodes | Internet-scale BGP routing |
| Inspection | Rule-based matching on DNS names, TLS SNI and HTTP Host | Behaviour of any specific commercial device |
| Measurements | Latency, loss, success rate, event timeline | Measurements of the real internet |

## Repository layout

```
orwox-network-simulation/
├── engine/          Simulation engine and command-line interface
├── web/             Browser front end (static files, deployed to GitHub Pages)
├── docs/            Protocol primer, architecture notes, contribution guide
├── .github/         Continuous integration and Pages workflows
└── README.md
```

## Running the simulation

Command line (Python 3.11+):

```bash
cd engine
python -m venv .venv && source .venv/bin/activate
pip install -e .
orwox-sim run --dpi on --cov off
orwox-sim run --dpi on --cov on
```

Browser:

```bash
cd web
python -m http.server 8080
```

Then open `http://localhost:8080`.

## Simulation model

The simulation is a **discrete-event simulation**. Every packet exchange is an event with a timestamp in a priority queue. Nodes consume events and schedule new ones, and the simulated clock jumps from one event to the next.

### Event loop

1. Pop the earliest event from the queue and set the simulated clock to its timestamp.
2. Pass the event to the node it targets.
3. The node returns zero or more new events, which are pushed onto the queue.
4. Repeat until the queue is empty or the simulation duration is reached.

### Lifecycle of one HTTPS request

| Step | Node | Action |
|---|---|---|
| 1 | Host | Application needs the address of the server name |
| 2 | Host → resolver | DNS query sent |
| 3 | Inspector | Observes the DNS query name if it is sent in plaintext |
| 4 | Resolver → Host | DNS answer returned |
| 5 | Host ↔ Server | TCP three-way handshake (SYN, SYN-ACK, ACK) |
| 6 | Host → Server | TLS ClientHello containing the SNI in plaintext |
| 7 | Inspector | Reads the SNI if it can see it and applies its policy |
| 8 | Server | TLS handshake completes and application data flows |

Each delivery delay is sampled from a normal distribution with a configurable mean and standard deviation. A packet can be dropped with a configurable probability.

## Parameters

Parameters are set in the browser controls or on the command line.

| Parameter | Meaning | Effect |
|---|---|---|
| Latency | One-way delay in milliseconds | Increases round-trip time for every step |
| Loss rate | Probability that a packet is dropped | Causes retransmissions and failures |
| DPI enabled | Whether the inspector is active | Turns rule matching on or off |
| Blocked names | Names the inspector matches | Defines the policy |
| Inspector action | Reset, drop or throttle on a match | Changes the failure signature |
| DNS mode | Plaintext, encrypted resolver, or model-specific option | Changes whether the query name is visible |
| Tunnel component | Enables a simulated transport modification | Changes what the inspector can read |

## Publishing the site

The site in `web/` is a static site and can be hosted on GitHub Pages.

1. Push this repository to GitHub.
2. Open the repository on GitHub and go to **Settings → Pages**.
3. Under **Build and deployment**, set **Source** to **GitHub Actions**.
4. Push to `main`. The workflow in `.github/workflows/pages.yml` uploads the `web/` folder and deploys it.
5. The site is available at `https://<owner>.github.io/<repository>/` once the workflow finishes. The **Actions** tab shows its progress.

Notes:
- The site uses only relative paths, so it works under a repository subpath.
- To test the same artifact locally, run the `python -m http.server` command from the `web/` folder.

## Testing

```bash
cd engine
pytest -q
```

- Unit tests cover each component: links, inspector rules, the simulated handshake fields and the event queue.
- Property tests check that the same seed always produces the same results.
- Statistical tests check that the loss rate and delay distributions match their parameters.

## Limitations and responsible use

- This is a **model**. It does not reproduce real ISP equipment, real inspection devices or any production software.
- Results are illustrative and do not replace real network measurements.
- The project is intended for **education and research**: understanding protocol design, the privacy implications of metadata, and the defensive side of traffic analysis.
- Do not use this project to interfere with other people's communications or to bypass controls you are not authorised to bypass.

## References

- RFC 791: Internet Protocol (IPv4)
- RFC 793: Transmission Control Protocol
- RFC 1035: Domain Names, implementation and specification
- RFC 6066, section 3: Server Name Indication
- RFC 8446: The Transport Layer Security (TLS) Protocol, Version 1.3
- RFC 8484: DNS Queries over HTTPS (DoH)
- RFC 7858: Specification for DNS over TLS (DoT)
- Kurose and Ross, *Computer Networking: A Top-Down Approach*

---

Maintained by ORWOX. Licensed under the MIT License.
