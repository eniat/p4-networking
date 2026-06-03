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
}

struct headers {
    Ethernet_t ethernet;
    ARP_t      arp;
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

    // ############################ NAT ACTIONS #######################

    action rewrite_dst_prefix(bit<16> new_prefix) {
        // Extract host
        bit<32> host = (bit<32>)(hdr.ipv4.dstAddr & 32w0x0000FFFF);
        // Build new IP and assign
        hdr.ipv4.dstAddr = (ip4_addr_t)(((bit<32>)new_prefix << 16) | host);
    }

    action rewrite_src_prefix(bit<16> new_prefix) {
        // Extract host
        bit<32> host = (bit<32>)(hdr.ipv4.srcAddr & 32w0x0000FFFF);
        // Build new IP and assign
        hdr.ipv4.srcAddr = (ip4_addr_t)(((bit<32>)new_prefix << 16) | host);
    }

    action nop() {}

    // ###################### NAT tables ###############

    // Destination table
    table dnat_table {
        key = {
            standard_metadata.ingress_port : exact;
            hdr.ipv4.dstAddr : lpm;
        }
        actions = {
            rewrite_dst_prefix;
            nop;
        }
        const default_action = nop();
        size = 16;
    }
    
    // Source table
    table snat_table {
        key = {
            standard_metadata.ingress_port : exact;
            hdr.ipv4.srcAddr : lpm;
        }
        actions = {
            rewrite_src_prefix;
            nop;
        }
        const default_action = nop();
        size = 16;
    }

    apply {
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

        log_msg("Packet from port {} to port {}\n", {standard_metadata.ingress_port, standard_metadata.egress_spec});

        
        if (hdr.ipv4.isValid()) {
            // Apply NAT rules 
            if (standard_metadata.ingress_port == 1){
                dnat_table.apply();
            } else {
                snat_table.apply();
            }

            // Calculate L4 header length for checksum calculation in the egress pipeline
            meta.l4Len = hdr.ipv4.totalLen - ((bit<16>)(hdr.ipv4.ihl) << 2);
        }
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