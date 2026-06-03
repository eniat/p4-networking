/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*
 * Define the headers the program will recognize
 */
 #define CPU_PORT 255

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<32> ip4_addr_t;
typedef bit<48> mac_addr_t;

header Ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16> etherType;
}

// Arp handling
header ARP_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8> hlen;
    bit<8> plen;
    bit<16> oper;
    mac_addr_t sha;
    ip4_addr_t spa;
    mac_addr_t tha;
    ip4_addr_t tpa;
}

header IPv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    tos;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4_addr_t srcAddr;
    ip4_addr_t dstAddr;
}

header TCP_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header UDP_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {
    bit<16>     l4Len; // checksum calculation: TCP hdr len + TCP payload len in bytes.
    bit<16> l4Port; // src or dest Port 
    bit<8> l4Proto; // 6 TCP 17 UDP
    bit<1> is_inside;
}

struct headers {
    Ethernet_t ethernet;
    ARP_t       arp;
    IPv4_t     ipv4;
    TCP_t      tcp;
    UDP_t      udp;

}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            0x0806: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action nop() {}

    // ############################# PAT actions ###################

    action pat_out(ip4_addr_t public_ip) {
        hdr.ipv4.srcAddr = public_ip;
    }

    action pat_in(ip4_addr_t private_ip) {
        hdr.ipv4.dstAddr = private_ip;
    }

    action set_inside() { 
        meta.is_inside = 1;
    }

    action mark_learned() {}

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
    }

    // ############################# port-forwarding actions ##########

    action port_fwd(ip4_addr_t internal_ip, bit<16> internal_port) {
        hdr.ipv4.dstAddr = internal_ip;

        if (hdr.tcp.isValid()) {
            hdr.tcp.dstPort = internal_port;
        } else if (hdr.udp.isValid()){
            hdr.udp.dstPort = internal_port;
        }
    }

    action port_fwd_rev(bit<16> external_port) {
        if (hdr.tcp.isValid()){
            hdr.tcp.srcPort = external_port;
        } else if (hdr.udp.isValid()) {
            hdr.udp.srcPort = external_port;
        }
    }

    action tcp_rst_reply() {
        standard_metadata.egress_spec = standard_metadata.ingress_port;

        //swap eth 
        mac_addr_t m = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = m;

        // swap ip
        ip4_addr_t ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = ip;

        // swap tcp ports 
        bit<16> p = hdr.tcp.srcPort;
        hdr.tcp.srcPort = hdr.tcp.dstPort;
        hdr.tcp.dstPort = p;

        // RST + ack
        hdr.tcp.ctrl = 6w20;
        hdr.tcp.ackNo = hdr.tcp.seqNo + 32w1;
        hdr.tcp.seqNo = 32w0;
    }

    // ############################# PAT Tables ##########

    table learn_table {
        key = {
            hdr.ipv4.srcAddr : exact;
            meta.l4Proto : exact;
            meta.l4Port : exact;
        }
        actions = { mark_learned; nop;}
        const default_action = nop();
        size = 4096;
    }

    table pat_in_table {
        key = {
            hdr.ipv4.dstAddr : exact;
            meta.l4Proto : exact;
            meta.l4Port : exact;
        }
        actions = { pat_in; nop;}
        const default_action = nop();
        size = 4096;
    }

    table pat_out_cfg {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = {pat_out; nop;}
        const default_action = nop();
        size = 4;
    }

    table inside_ports {
        key = {
            standard_metadata.ingress_port : exact;
        }
        actions = { set_inside; nop;}
        const default_action = nop();
        size = 8;
    }

    // ########################### Port-forwarding table ########

    table port_fwd_table {
        key = {
            hdr.ipv4.dstAddr :exact;
            meta.l4Proto : exact;
            meta.l4Port : exact;
        }
        actions = {port_fwd; nop;}
        const default_action = nop();
        size = 1024;
    }

    table port_fwd_rev_table {
        key = {
            hdr.ipv4.srcAddr : exact;
            meta.l4Proto : exact;
            meta.l4Port : exact;
        }
        actions = {port_fwd_rev; nop;}
        const default_action = nop;
        size = 1024;
    }

    apply {
        meta.is_inside = 0;
        inside_ports.apply();

        if (standard_metadata.ingress_port == 1) {
            // Send packets from port 1 to port 2
            standard_metadata.egress_spec = 2;
        } else {
            // Send packet from port 2 to port 1
            standard_metadata.egress_spec = 1;
        }

        // Forward ARP
        if (hdr.arp.isValid()) {
            log_msg("ARP from port {} to port {}\n", {standard_metadata.ingress_port, standard_metadata.egress_spec});
            return;
        }

        // PAT 
        if (hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid())) {
            
            meta.l4Proto = hdr.ipv4.protocol;
            // Calculate L4 header length for checksum calculation in the egress pipeline
            meta.l4Len = hdr.ipv4.totalLen - ((bit<16>)(hdr.ipv4.ihl) << 2);

            // Outbound 
            if (meta.is_inside == 1) {
                meta.l4Port = hdr.tcp.isValid() ? hdr.tcp.srcPort : hdr.udp.srcPort;

                port_fwd_rev_table.apply();
                // recompute after potential rewrite 
                meta.l4Port = hdr.tcp.isValid() ? hdr.tcp.srcPort : hdr.udp.srcPort;

                bool learned = learn_table.apply().hit;
                if (!learned) {
                    send_to_cpu();
                    return;
                }

                // Rewrite srcIP 
                pat_out_cfg.apply();
            }

            // Inbound 
            else {
                meta.l4Port = hdr.tcp.isValid() ? hdr.tcp.dstPort : hdr.udp.dstPort;

                // port forwarding
                bool pf_hit = port_fwd_table.apply().hit;
                if (!pf_hit){
                    bool hit = pat_in_table.apply().hit;
                    if (!hit) {
                        if (hdr.tcp.isValid()){
                            tcp_rst_reply();
                        } else {
                            mark_to_drop(standard_metadata);
                        }
                    }
                }
            }
        }

        log_msg("Packet from port {} to port {}\n", {standard_metadata.ingress_port, standard_metadata.egress_spec});
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply { 
        // This block do not use any if statement to check the validity of the header, as it is embedded in the update_checksum funciton.

        // IPv4 checksum calculation
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);

        // TCP checksum calculation
        update_checksum_with_payload(hdr.tcp.isValid(),
            { hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.l4Len,
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.res,
                hdr.tcp.ecn,
                hdr.tcp.ctrl,
                hdr.tcp.window,
                16w0,
                hdr.tcp.urgentPtr
            },
            hdr.tcp.checksum, HashAlgorithm.csum16);

            // UDP checksum calculation
            update_checksum_with_payload(hdr.udp.isValid(),
                { hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    8w0,
                    hdr.ipv4.protocol,
                    meta.l4Len,
                    hdr.udp.srcPort,
                    hdr.udp.dstPort,
                    hdr.udp.length_,
                    16w0 // checksum
                },
                hdr.udp.checksum, HashAlgorithm.csum16);      

    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
		// parsed headers have to be added again into the packet
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
	}
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
	MyParser(),
	MyVerifyChecksum(),
	MyIngress(),
	MyEgress(),
	MyComputeChecksum(),
	MyDeparser()
) main;