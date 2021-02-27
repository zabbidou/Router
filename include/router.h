#pragma once

#include <stdlib.h>

#define IP_OFF (sizeof(struct ether_header))
#define ICMP_OFF (IP_OFF + sizeof(struct iphdr))

// struct pt routing table
typedef struct node {
	int is_end; // 0-> nu e capat
				// 1-> e capat

    struct node* children[4];
	// children[0] -> 00
	// children[1] -> 01
	// children[2] -> 10
	// children[3] -> 11

	char* next_hop;
	int interface;
} routing_node;

typedef struct {
    uint32_t ip;
    uint8_t mac[6];
} arp_entry;


routing_node* parse_routing_table();
void dec_to_bin (uint32_t n);
void parse_address(char* string, struct in_addr* ip);
uint16_t incremental_checksum(uint8_t old_ttl_n, uint16_t old_checksum);
