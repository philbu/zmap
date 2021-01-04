
/*
 * Jan Rüth 2018, Philippe Buschmann 2021
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 */

/* module to perform IETF QUIC (draft-32) enumeration */

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#include "../../lib/includes.h"
#include "../../lib/xalloc.h"
#include "../../lib/lockfd.h"
#include "../../lib/pbm.h"
#include "logger.h"
#include "probe_modules.h"
#include "packet.h"
#include "aesrand.h"
#include "state.h"
#include "module_udp.h"
#include "module_quic_initial.h"

#define UNUSED __attribute__((unused))


static inline uint64_t make_quic_conn_id(char a, char b, char c, char d, char e, char f, char g, char h) {
	return (uint64_t)(a) |
		(uint64_t)(b) << 8 |
		(uint64_t)(c) << 16 |
		(uint64_t)(d) << 24 |
		(uint64_t)(e) << 32 |
		(uint64_t)(f) << 40 |
		(uint64_t)(g) << 48 |
		(uint64_t)(h) << 56 ;
}

static int num_ports;

probe_module_t module_quic_initial;
static char filter_rule[30];
uint64_t connection_id;

uint8_t** checker_bitmap;

void quic_initial_set_num_ports(int x) { num_ports = x; }

void printBuffer(uint8_t* buf, int len) {
  for (int i=0; i<len; i++){
    printf("%02x", *(buf+i));
  }
  printf("\n");
}

int quic_initial_global_initialize(struct state_conf *conf) {
	num_ports = conf->source_port_last - conf->source_port_first + 1;
	
	char port[16];
	sprintf(port, "%d", conf->target_port);
	// answers have the target port as source
	memcpy(filter_rule, "udp src port \0", 14);

	module_quic_initial.pcap_filter = strncat(filter_rule, port, 16);
	// TODO change length of pcap
  module_quic_initial.pcap_snaplen = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + QUIC_PACKET_LENGTH;

	connection_id = make_quic_conn_id('S', 'C', 'A', 'N', 'N', 'I', 'N', 'G');
	checker_bitmap = pbm_init();
	return EXIT_SUCCESS;
}


int quic_initial_global_cleanup(__attribute__((unused)) struct state_conf *zconf,
		__attribute__((unused)) struct state_send *zsend,
		__attribute__((unused)) struct state_recv *zrecv)
{
	return EXIT_SUCCESS;
}

int quic_initial_init_perthread(void* buf, macaddr_t *src,
		macaddr_t *gw, __attribute__((unused)) port_h_t dst_port,\
		__attribute__((unused)) void **arg_ptr)
{
  // set length of udp msg
	int udp_send_msg_len = QUIC_PACKET_LENGTH;
	//log_debug("prepare", "UDP PAYLOAD LEN: %d", udp_send_msg_len);
  
	memset(buf, 0, MAX_PACKET_SIZE);
	struct ether_header *eth_header = (struct ether_header *) buf;
	make_eth_header(eth_header, src, gw);
	struct ip *ip_header = (struct ip*)(&eth_header[1]);
	uint16_t len = htons(sizeof(struct ip) + sizeof(struct udphdr) + udp_send_msg_len);
	//log_debug("prepare", "IP LEN IN HEX %h", len);
	make_ip_header(ip_header, IPPROTO_UDP, len);

	struct udphdr *udp_header = (struct udphdr*)(&ip_header[1]);
	len = sizeof(struct udphdr) + udp_send_msg_len;
	make_udp_header(udp_header, zconf.target_port, len);

	char* payload = (char*)(&udp_header[1]);

	module_quic_initial.packet_length = sizeof(struct ether_header) + sizeof(struct ip)
				+ sizeof(struct udphdr) + udp_send_msg_len;
	assert(module_quic_initial.packet_length <= MAX_PACKET_SIZE);
	memset(payload, 0, udp_send_msg_len);

	return EXIT_SUCCESS;
}


int quic_initial_make_packet(void *buf, UNUSED size_t *buf_len, ipaddr_n_t src_ip, ipaddr_n_t dst_ip,
	UNUSED uint8_t ttl, uint32_t *validation, int probe_num, UNUSED void *arg)
{
	struct ether_header *eth_header = (struct ether_header *) buf;
	struct ip *ip_header = (struct ip*) (&eth_header[1]);
	struct udphdr *udp_header= (struct udphdr *) &ip_header[1];

	ip_header->ip_src.s_addr = src_ip;
	ip_header->ip_dst.s_addr = dst_ip;
	udp_header->uh_sport = htons(get_src_port(num_ports, probe_num,
	                             validation));

	uint8_t *payload = (uint8_t *) &udp_header[1];
	int payload_len = 0;

	memset(payload, 0, QUIC_PACKET_LENGTH);

	quic_long_hdr* common_hdr = (quic_long_hdr*)payload;

  // set header flags
  uint8_t protected_header_flags = HEADER_FLAG_RESERVED_BITS | HEADER_FLAG_PACKET_NUMBER_LENGTH;
  uint8_t public_header_flags = HEADER_FLAG_FORM_LONG_HEADER | HEADER_FLAG_FIXED_BIT | HEADER_FLAG_TYPE_INITIAL;
  common_hdr->header_flags = protected_header_flags | public_header_flags;
  common_hdr->version = QUIC_VERSION_FORCE_NEGOTIATION;
	common_hdr->dst_conn_id_length = HEADER_CONNECTION_ID_LENGTH;
	common_hdr->dst_conn_id = connection_id;
  common_hdr->src_conn_id_length = 0x00;
  common_hdr->token_length = 0x00;
  common_hdr->length = QUIC_PACKET_LENGTH - sizeof(quic_long_hdr) + sizeof(common_hdr->packet_number);
  common_hdr->packet_number = 0x0000;

  // Padding was already done with memset
  payload_len = QUIC_PACKET_LENGTH;

	// Update the IP and UDP headers to match the new payload length
	ip_header->ip_len   = htons(sizeof(struct ip) + sizeof(struct udphdr) + payload_len);
	udp_header->uh_ulen = ntohs(sizeof(struct udphdr) + payload_len);

	ip_header->ip_sum = 0;
	ip_header->ip_sum = zmap_ip_checksum((unsigned short *) ip_header);

	return EXIT_SUCCESS;
}

void quic_initial_print_packet(FILE *fp, void* packet)
{
	struct ether_header *ethh = (struct ether_header *)packet;
	struct ip *iph = (struct ip *)&ethh[1];
	struct udphdr *udph = (struct udphdr *)(&iph[1]);
	fprintf(fp, "udp { source: %u | dest: %u | checksum: %#04X }\n",
		ntohs(udph->uh_sport), ntohs(udph->uh_dport),
		ntohs(udph->uh_sum));
	fprintf_ip_header(fp, iph);
	fprintf_eth_header(fp, ethh);
	fprintf(fp, "------------------------------------------------------\n");
}

void quic_initial_process_packet(const u_char *packet, UNUSED uint32_t len, fieldset_t *fs, UNUSED uint32_t *validation,
			__attribute__((unused)) struct timespec ts)
{
	/*struct ip *ip_hdr = (struct ip *) &packet[sizeof(struct ether_header)];
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		struct udphdr *udp = (struct udphdr *) ((char *) ip_hdr + ip_hdr->ip_hl * 4);

		
		// Verify that the UDP length is big enough for the header and at least one byte
		uint16_t data_len = ntohs(udp->uh_ulen);
		if (data_len > sizeof(struct udphdr)) {
			uint8_t* payload = (uint8_t*)&udp[1];
			if (data_len > (QUIC_HDR_LEN_HASH - 13 - sizeof(struct udphdr))) {
                quic_common_hdr* quic_header = ((quic_common_hdr*)payload);
				if(quic_header->dst_connection_id == connection_id) {
					fs_add_string(fs, "classification", (char*) "quic", 0);
					fs_add_uint64(fs, "success", 1);
				}
				
                
				// probably we got back a version packet
				if (data_len < (QUIC_HDR_LEN_HASH + CLIENTHELLO_MIN_SIZE - sizeof(struct udphdr))) {
					quic_version_neg* vers = (quic_version_neg*)payload;
					if ((vers->public_flags & PUBLIC_FLAG_HAS_VERS) > 0) {
						// contains version flag
						int num_versions = (data_len - sizeof(struct udphdr) - 8 - 1) / 4;
                        if (num_versions > 0) {

                            // create a list of the versions
                            // 4 bytes each + , + [SPACE] + \0
                            char* versions = malloc(num_versions * sizeof(uint32_t) + (num_versions-1)*2 + 1);
                            int next_ver = 0;
                            
                            if (*((uint32_t*)&vers->versions[0]) == MakeQuicTag('Q', '0', '0', '1')) {
                                // someone replied with our own version... probalby UDP echo
                                fs_modify_string(fs, "classification", (char*) "udp", 0);
                                fs_modify_uint64(fs, "success", 0);
                                free(versions);
                                return;
                            }
                            for (int i = 0; i < num_versions; i++) {
                                memcpy(&versions[next_ver], &vers->versions[i], sizeof(uint32_t));
                                next_ver += 4;
                                if(i != num_versions-1) {
                                    versions[next_ver++] = ',';
                                    versions[next_ver++] = ' ';
                                }
                            }
                            versions[next_ver] = '\0';
                            fs_add_string(fs, "versions", versions, 1);
                            //fs_add_binary(fs, "versions", num_versions * sizeof(uint32_t), vers->versions, 0);
                            
                        }
                    }else if ((vers->public_flags & PUBLIC_FLAG_HAS_RST) > 0) {
                        fs_modify_string(fs, "info", (char*) "RST", 0);
                    }
				}
			}
		} else {
			fs_add_string(fs, "classification", (char*) "udp", 0);
			fs_add_uint64(fs, "success", 0);
		}
	}*/
}

int quic_initial_validate_packet(const struct ip *ip_hdr, uint32_t len,
		__attribute__((unused))uint32_t *src_ip, UNUSED uint32_t *validation)
{
	if (ip_hdr->ip_p == IPPROTO_UDP) {
		if ((4*ip_hdr->ip_hl + sizeof(struct udphdr)) > len) {
			// buffer not large enough to contain expected udp header
			return 0;
		}
		
		int already_checked = pbm_check(checker_bitmap, ntohl(ip_hdr->ip_src.s_addr));
		if (already_checked) {
			return 0;
		}
		
		pbm_set(checker_bitmap, ntohl(ip_hdr->ip_src.s_addr));
		
		return 1;
	}
	
	return 0;
}

static fielddef_t fields[] = {
	{.name = "classification", .type="string", .desc = "packet classification"},
	{.name = "success", .type="int", .desc = "is response considered success"},
	{.name = "versions", .type="string", .desc = "versions if reported"},
  {.name = "info", .type="string", .desc = "info"}
};

probe_module_t module_quic_initial = {
	.name = "quic_initial",
	// we are resetting the actual packet length during initialization of the module
	.packet_length = sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + QUIC_PACKET_LENGTH,
	// this gets replaced by the actual port during global init
	.pcap_filter = "udp",
	// this gets replaced by the actual payload we expect to get back
	.pcap_snaplen = 1500,
	.port_args = 1,
	.thread_initialize = &quic_initial_init_perthread,
	.global_initialize = &quic_initial_global_initialize,
	.make_packet = &quic_initial_make_packet,
	.print_packet = &quic_initial_print_packet,
	.validate_packet = &quic_initial_validate_packet,
	.process_packet = &quic_initial_process_packet,
	.close = &quic_initial_global_cleanup,
	.helptext = "Probe module that sends QUIC CHLO packets to hosts.",
	.fields = fields,
	.numfields = sizeof(fields)/sizeof(fields[0])
};