# P4 NAT and PAT Network Simulation

A programmable networking project implementing Network Address Translation (NAT), Port Address Translation (PAT), dynamic flow learning and TCP port forwarding using P4, BMv2/Stratum, P4Runtime and Mininet.

The project models a routed network with private home devices, cloud services and web servers. Two programmable switches sit on the path: `s1` performs PAT for the home network and `s2` performs prefix-based NAT for the web network.

## What this project demonstrates
- P4 packet parsing for Ethernet, ARP, IPv4, TCP and UDP.
- Prefix-based source and destination NAT.
- TCP/UDP Port Address Translation.
- Dynamic flow learning through a Python P4Runtime controller.
- Runtime table configuration from JSON files.
- Port forwarding rules exposed through a REST API.
- IPv4, TCP and UDP checksum recomputation after rewriting.
- Mininet-based testing of a multi-network topology.

## Network design
The topology contains home devices (`homePC`, `tablet`, `phone`), a home router, a simulated internet router, a cloud network with `cloud1`, and a web network with `web1` and `web2`.

Two P4 switches sit between these networks:
- `s1` runs the PAT program for the home network.
- `s2` runs the NAT program for the web network.

The home network uses private addresses behind `s1`. Outbound TCP/UDP traffic can be rewritten to a public-facing address. The web network sits behind `s2`, which rewrites configured IPv4 prefixes using source and destination NAT tables.

## About this project

Built on a provided P4Runtime skeleton (topology, Makefile, controller
scaffolding and helper libraries). My work was implementing the NAT and PAT
functionality on top of it:

- **`p4src/pat.p4`** — the Port Address Translation data plane: outbound
  source rewriting, CPU-punting and learning of unknown flows, return-path
  translation, TCP/UDP handling, and static port forwarding.
- **`p4src/nat.p4`** — the prefix-based NAT data plane: source/destination
  NAT tables, ARP pass-through, and checksum recomputation after rewrites.
- The flow-learning logic and REST API added inside the provided controller.

## Licensing

Published for viewing and portfolio review only, not licensed for reuse.
See `NOTICE` for the breakdown of my additions, the provided skeleton, and
third-party Apache-2.0 components, and `LICENSE` for the Apache-2.0 text.

## Main components

### PAT data plane
`p4src/pat.p4` implements port-aware translation. It marks inside ports, rewrites outbound source IPs, sends unknown outbound flows to the CPU port, rewrites inbound destination IPs for learned return traffic, supports TCP/UDP and handles unmatched inbound traffic by dropping it or returning a TCP reset.

It also includes static TCP port forwarding through `port_fwd_table` and `port_fwd_rev_table`.

### NAT data plane
`p4src/nat.p4` implements prefix-based NAT. `dnat_table` rewrites destination prefixes and `snat_table` rewrites source prefixes. Matching is based on ingress port and IPv4 prefix.

ARP packets are forwarded without translation. IPv4, TCP and UDP checksums are recalculated after address or port changes.

### Controller
`controller.py` connects to the P4 switches using P4Runtime. It installs the compiled P4 pipelines, loads runtime table entries and manages dynamic PAT mappings.

For PAT, the controller learns outbound TCP/UDP flows sent to the CPU port and installs return-path entries so inbound replies can be translated back to the original private host.

## REST API
The controller exposes a small Flask API on port `8080`:

```text
GET /api/status
GET /api/switches
GET /api/nat/list
GET /api/port-forward/list
GET /api/port-forward/add/<internal_ip>/<internal_port>/<external_port>
```

Example:

```bash
curl http://localhost:8080/api/status
curl http://localhost:8080/api/port-forward/add/192.168.0.10/8080/9000
```

## Repository structure
```text
.
├── controller.py              # P4Runtime controller and REST API
├── controller.json            # Switch/controller configuration
├── docker-compose.yml         # Mininet/Stratum container setup
├── Makefile                   # Build and run commands
├── p4src/
│   ├── nat.p4                 # Prefix-based NAT program
│   └── pat.p4                 # PAT and port-forwarding program
├── mininet/
│   ├── topo.py                # Network topology
│   ├── s1-runtime.json        # PAT runtime entries
│   ├── s2-runtime.json        # NAT runtime entries
│   └── flask_ip.py            # Test HTTP service
├── proto/                     # P4Runtime protobuf definitions
├── util/                      # P4Runtime helper libraries
└── docs/                      # Generated helper documentation
```

## Requirements
This project is intended to run inside the supplied development container or an equivalent Linux environment with Docker support.

Required tools: Docker, Docker Compose, Python 3, Make, P4 compiler image and the Stratum/BMv2 Mininet environment.

The repository includes `.devcontainer.json` for a prepared container setup.

## Setup and running
Pull required container images:

```bash
make deps
```

Compile the P4 programs:

```bash
make p4-build
```

This generates compiled BMv2 JSON and P4Info files under `p4src/build/`.

Start the Mininet topology:

```bash
make start
```

Start the controller in a second terminal:

```bash
make controller
```

Attach to the Mininet CLI:

```bash
make mn-cli
```

Stop the topology:

```bash
make stop
```

## Example testing
From the Mininet CLI:

```bash
nodes
net
homePC curl http://10.10.0.32:8080
homePC iperf3 -c 10.10.0.32
```

The included Flask test server returns the source IP it sees, which helps validate address translation behaviour.

While the controller is running, the API can be queried from another terminal:

```bash
curl http://localhost:8080/api/status
```

## Notes and limitations
- PAT is implemented for TCP and UDP because port numbers are required.
- ARP is forwarded directly and is not translated.
- The project is designed for a controlled Mininet/Stratum lab environment.
- The implementation demonstrates programmable data-plane behaviour rather than production-grade routing, firewalling or NAT hardening.
