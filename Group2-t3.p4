/* Include P4 core library */
#include <core.p4>
/* Include V1 Model switch architecture */
#include <v1model.p4>

typedef bit<9>  egressSpec_t;

/* Describes the format of an Ethernet header */
header Ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> typ;
}

/* Describes the format of an IPv4 header WITHOUT options. */
header IPv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  tos;
    bit<16> total_len;
    bit<16> id;
    bit<3>  flags;
    bit<13> offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

/* Describes the format of an IPv4 header WITHOUT options. */
header IPv6_h {
    bit<4>  	version;
    bit<8>  	traffic_class;
    bit<20> 	flow_label;
    bit<16> 	payload_length;
    bit<8>  	next_header;
    bit<8>  	hop_limit;
    bit<128> 	src;
    bit<128>  	dst;
}

/*
Structure of user metadata.
No user metadata is needed for this example so the struct is empty.
*/
struct user_metadata_t {}
/* Structure of parsed headers. */
struct headers_t {
    Ethernet_h ethernet;
    IPv4_h     ipv4;
    IPv6_h     ipv6;
}

/* The parser describes the state machine used to parse packet headers. */
parser MyParser(packet_in pkt, out headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    /* The state maachine always begins parsing with the start state */
    state start {
        /* Fills in the values of the Ethernet header and sets the header as valid. */
        pkt.extract(hdr.ethernet);
        /* Transition to the next state based on the value of the Ethernet type field. */
        transition select(hdr.ethernet.typ) {
	    	/* Parsing IPv4 source: https://opennetworking.org/wp-content/uploads/2020/12/p4-cheat-sheet.pdf */
	    	0x0800: parse_ipv4;
	    	0x86DD: parse_ipv6;
        }
    }

    state parse_ipv4 {
		/* Parse IPv4 header and accept it */ 
		pkt.extract(hdr.ipv4);
		transition select(hdr.ipv4.proto) {
			6: parse_tcp;
			17: parse_udp;
			default: accept;
		}
    }

    state parse_ipv6 {
		/* Also parse IPv6 header and accept it */
		pkt.extract(hdr.ipv6);
		transition select(hdr.ipv6.next_header) {
			6: parse_tcp;
			17: parse_udp;
			default: accept;
		}	
    }

	state parse_tcp {
		pkt.extract(hdr.tcp);
		transition accept;
	}

	state parse_udp {
		pkt.extract(hdr.udp);
		transition accept;
	}
}

/* This contol block is not used for the lab. */
control MyVerifyChecksum(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/*
Control flow prior to egress port selection.
egress_spec can be assigned a value to control which output port a packet will go to.
egress_port should not be accessed.
 */
control MyIngress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
    /* An action that takes the desired egress port as an argument. */
    action set_egress(bit<9> port) {
        smd.egress_spec = port;
    }
    /* An action that will cause the packet to be dropped. */
    action drop() {
        mark_to_drop(smd);
    }

    /* Source: https://github.com/p4lang/tutorials/tree/master/exercises/basic */
    action ipv4_forward(bit<48> dst, egressSpec_t port) {
        smd.egress_spec = port;
        hdr.ethernet.src = hdr.ethernet.dst;
        hdr.ethernet.dst = dst;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action ipv6_forward(bit<48> dst, egressSpec_t port) {
        smd.egress_spec = port;
        hdr.ethernet.src = hdr.ethernet.dst;
        hdr.ethernet.dst = dst;
        hdr.ipv6.hop_limit = hdr.ipv6.hop_limit - 1;
    }

    table ipv4_forwarding {
        /* Values that will be used to look up an entry. */
        key = { hdr.ipv4.dst: lpm; }
        /* All possible actions that may result from a lookup or table miss. */
        actions = {
	   		ipv4_forward;
            set_egress;
            drop;
	    	NoAction;
        }
		size = 1024;
        /* The action to take when the table does not find a match for the supplied key. */
        default_action = drop;
    }

    table ipv6_forwarding {
        /* Values that will be used to look up an entry. */
        key = { hdr.ipv6.dst: lpm; }
        /* All possible actions that may result from a lookup or table miss. */
        actions = {
            ipv6_forward;
	    	set_egress;
            drop;
	    	NoAction;
        }
        size = 1024;
		/* The action to take when the table does not find a match for the supplied key. */
        default_action = drop;
    }

    apply {
		if (hdr.ipv4.isValid()) {
	    	ipv4_forwarding.apply();
		}

        if (hdr.ipv6.isValid()) {
            ipv6_forwarding.apply();
        }
    }
}

/*
Control flow after egress port selection.
egress_spec should not be modified. egress_port can be read but not modified. The packet can still be dropped.
*/
control MyEgress(inout headers_t hdr, inout user_metadata_t umd, inout standard_metadata_t smd) {
	table multicast_broadcast_filter {
		key = { hdr.ethernet.dst: ternary; }

		actions = {
			drop;
			NoAction;
		}

		default_action = drop;
	}

    apply {
		multicast_broadcast_filter.apply();
	}
}

/* This contol block is not used for the lab. */
control MyComputeChecksum(inout headers_t hdr, inout user_metadata_t umd) {
    apply {}
}

/* The deparser constructs the outgoing packet by reassembling headers in the order specified. */
control MyDeparser(packet_out pkt, in headers_t hdr) {
    apply {
        /* Emitting a header appends the header to the out going packet only if the header is valid. */
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
		pkt.emit(hdr.ipv6);
    }
}

/* This instantiate the V1 Model Switch */.
V1Switch(
 MyParser(),
 MyVerifyChecksum(),
 MyIngress(),
 MyEgress(),
 MyComputeChecksum(),
 MyDeparser()
) main;
