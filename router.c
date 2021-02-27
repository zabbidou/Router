#include "include/skel.h"
#include "include/router.h"
#include "queue.h"
#include <stdio.h>
#include <stdlib.h>
#include <net/if_arp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

#define null NULL
#define true 1
#define false 0
#define ETH_BROADCAST {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
// exit code-urile de la is_for_router
#define ICMP_PACKET 2
#define ARP_PACKET 1
#define NOT_FOR_FOUTER 0

// avem nevoie de asta pt ca unele functii scriu rezultatul la adresa unui 
// struct in_addr, si sa nu mai stau sa declar de fiecare data aceeasi chestie
struct in_addr temp;

// declaram asta global pentru ca e folosita peste tot
routing_node* root;

// construieste 4-ary trie-ul
routing_node* parse_routing_table() {
    FILE* in;
    char* line = null;
    ssize_t is_reading;
    size_t len = 0;
    
    // deschidem cu fopen ca oricum stim ca avem numa ascii
    in = fopen("rtable.txt", "r");
    // verificam daca am deschis cum trb
    if (in == null) {
        printf("Can't find file!!!\n");
        exit(-1);
    }

    struct in_addr mask;
    routing_node* root = (routing_node*)calloc(1, sizeof(routing_node)); 
    routing_node* current_node = root;

    while ((is_reading = getline(&line, &len, in)) != -1) {
        // addr
        parse_address(strtok(line, " "), &temp);
        // nexthop
        char* next_hop = strtok(null, " ");
        // mask
        parse_address(strtok(null, " "), &mask);
        int interface = atoi(strtok(null, " "));
        uint32_t prefix = temp.s_addr & mask.s_addr;
        current_node = root;
        // parcurgem o adresa ip
        for (int i = 30; i >= 0; i = i - 2) {
            uint32_t shifter = 3 << i;
            uint32_t result = (shifter & prefix);
            result = result >> i;

            // nr de biti impari in masca, trebuie sa setam 2 noduri
            if (((shifter & mask.s_addr) >> i) == 2) {
                routing_node* node1 = calloc(1, sizeof(routing_node));
                routing_node* node2 = calloc(1, sizeof(routing_node));

                node1->is_end = 1;
                node1->next_hop = (char*)calloc(16, sizeof(char));
                memcpy(node1->next_hop, next_hop,  16);
                node1->interface = interface;

                node2->is_end = 1;
                node2->next_hop = (char*)calloc(16, sizeof(char));
                memcpy(node2->next_hop, next_hop,  16);
                node2->interface = interface;
                
                if (result < 2) { // result = 0/1 -> setam nodurile cu 0*
                    if (current_node->children[0] == null) {
                        current_node->children[0] = node1;
                    } else {
                        free(node1);
                    }

                    if (current_node->children[1] == null) {
                        current_node->children[1] = node2;
                    } else {
                        free(node2);
                    }
                } else { // result = 2/3 -> setam nodurile cu 1*
                    if (current_node->children[2] == null) {
                        current_node->children[2] = node1;
                    } else {
                        free(node1);
                    }
                    
                    if (current_node->children[3] == null) {
                        current_node->children[3] = node2;
                    } else {
                        free(node2);
                    }
                }

                break;
            }

            if ((shifter & mask.s_addr) == 0) { // nr de biti pari in masca
                current_node->is_end = 1;
                current_node->next_hop = (char*)calloc(16, sizeof(char));
                memcpy(current_node->next_hop, next_hop,  16);
                current_node->interface = interface;
                break;
            }

            // daca mask len este par, are voie sa suprascrie un nod, 
            // pt a trece peste cazul in care ocupa 2 noduri

            if (current_node->children[result] == null) {
                routing_node* node = (routing_node*)calloc(1, sizeof(routing_node));
                current_node->children[result] = node;
            }
            
            current_node = current_node->children[result];
        }
    }

    return root;
}
// cauta in O(1) in trie
routing_node* search_routing_table(routing_node* root, uint32_t ip_to_search) {
    routing_node* current_node = root;
    routing_node* last_stop = null;
    
    for (int i = 30; i >= 0; i = i - 2) {
        uint32_t shifter = 3 << i;
        uint32_t result = (shifter & ip_to_search);
        result = result >> i;

        if (current_node->is_end == 1) {
            last_stop = current_node;
        }

        if (current_node->children[result] != null) {
            current_node = current_node->children[result];
        } else {
            break;
        }
    }
    
    if (last_stop != null) {
        return last_stop;
    } else {
        return null;
    }
}

// un wrapper convenient pentru mine
void parse_address(char* string, struct in_addr* ip) {
    if (string == null) {
        printf("Null string\n");
        exit(-1);
    }

    int error = inet_aton(string, ip);
    ip->s_addr = ntohl(ip->s_addr);
    
    if (error == 0) {
        printf("Invalid addr: %s\n", string);
        exit(-1);
    }
}

// Initializeaza tabela arp cu 4 intrari (ca na, stim ca are 4)
// Poate fi adaptat foarte usor intr-o lista simplu inlantuita
// pentru o lungime nespecificata, dar nu a fost nevoie
arp_entry* init_arp() {
    arp_entry* table = (arp_entry*)calloc(4, sizeof(arp_entry));
    
    for (int i = 0; i < 4; i++) {
        table[i].ip = 0;
    }
    
    return table;
}

// trimite ce pachete asteptau arp reply-ul primit
void send_packets_in_queue(arp_entry table, queue q) {
    queue new_q = queue_create();
    packet* m;

    while (!queue_empty(q)) {
        m = (packet*)queue_deq(q);
        struct iphdr *ip_hdr = (struct iphdr *)(m->payload + IP_OFF);
        struct ether_header *eth_hdr = (struct ether_header *)m->payload;
        temp.s_addr = ip_hdr->daddr;
        
        if (table.ip == ip_hdr->daddr) {
            memcpy(eth_hdr->ether_dhost, table.mac, 6);
            send_packet(m->interface, m);
        } else {
            queue_enq(new_q, m);
        }
    }

    q = new_q;
}

// primeste un arp reply si il pune in tabela
void memorise_arp(packet arp_reply, arp_entry* table, queue q) {
    struct ether_header *eth_hdr = (struct ether_header *)arp_reply.payload;
	struct ether_arp *arp_hdr = (struct ether_arp*)(arp_reply.payload + sizeof(struct ether_header));
    
    char string_ip[20];
    sprintf(string_ip, "%d.%d.%d.%d", arp_hdr->arp_spa[0], arp_hdr->arp_spa[1], arp_hdr->arp_spa[2], arp_hdr->arp_spa[3]);
    inet_aton(string_ip, &temp);

    table[arp_reply.interface].ip = temp.s_addr;
    memcpy(table[arp_reply.interface].mac, eth_hdr->ether_shost, 6);

    send_packets_in_queue(table[arp_reply.interface], q);
}

// construieste un arp request si il trimite
void send_arp_request(packet tosend) {
    packet* request = calloc(1, sizeof(packet));
    request->len = sizeof(struct ether_header) + sizeof(struct ether_arp);
    request->interface = tosend.interface;

    struct iphdr *to_send_ip_hdr = (struct iphdr *)(tosend.payload + IP_OFF);
    struct ether_header *eth_hdr = (struct ether_header *)request->payload;
    struct ether_arp *arp_hdr = (struct ether_arp*)(request->payload + sizeof(struct ether_header));

    memset(eth_hdr->ether_dhost, 0xFF, 6);
    get_interface_mac(request->interface, eth_hdr->ether_shost);
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);
    
    arp_hdr->arp_hrd = htons(ARPHRD_ETHER);
    arp_hdr->arp_pro = htons(ETHERTYPE_IP);
    arp_hdr->arp_hln = 6;
    arp_hdr->arp_pln = 4;
    arp_hdr->arp_op = htons(ARPOP_REQUEST);

    get_interface_mac(request->interface, arp_hdr->arp_sha);
    char* ip_s = get_interface_ip(request->interface);
    inet_aton(ip_s, &temp);

    memcpy(arp_hdr->arp_spa, &(temp.s_addr), 4);
    memset(arp_hdr->arp_tha, 0, 6);
    memcpy(arp_hdr->arp_tpa, &(to_send_ip_hdr->daddr), 4);

    send_packet(request->interface, request);
}

// trimite un arp reply ca raspuns la arp request destinat routerului
void send_arp_reply(packet *m) {
    struct ether_header *eth_hdr = (struct ether_header *)m->payload;
    struct ether_arp *arp_hdr = (struct ether_arp*)(m->payload + sizeof(struct ether_header));

    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    get_interface_mac(m->interface, eth_hdr->ether_shost);

    arp_hdr->arp_op = htons(ARPOP_REPLY);
    memcpy(arp_hdr->arp_tha, arp_hdr->arp_sha, 6);
    memcpy(arp_hdr->arp_sha, eth_hdr->ether_shost, 6);

    inet_aton(get_interface_ip(m->interface), &temp);
    memcpy(arp_hdr->arp_tpa, arp_hdr->arp_spa, 4);
    memcpy(arp_hdr->arp_spa, &(temp.s_addr), 4);

    send_packet(m->interface, m);
}

// cauta mac-ul in arp table
uint8_t* get_mac(arp_entry* table, uint32_t ip) {
    ip = ntohl(ip);

    for (int i = 0; i < 4; i++) {
        if (table[i].ip == 0) {
            continue;
        }

        if (table[i].ip == ip) {
            return table[i].mac;
        }
    }

    return NULL;
}

// self explanatory
bool is_ip_checksum_good(struct iphdr *ip_hdr) {
    uint16_t old_checksum = ip_hdr->check;
    ip_hdr->check = 0;
    uint16_t new_checksum = ip_checksum(ip_hdr, sizeof(struct iphdr));
    ip_hdr->check = old_checksum;

    if (new_checksum == old_checksum) {
        return true;
    }
    
    return false;
}

// self explanatory
bool is_icmp_checksum_good(packet m) {
    struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);

    uint16_t old_checksum = icmp_hdr->checksum;
    icmp_hdr->checksum = 0;
    uint16_t icmp_checksum = ip_checksum(m.payload + ICMP_OFF, m.len - ICMP_OFF);
    icmp_hdr->checksum = old_checksum;

    if (icmp_checksum == old_checksum) {
        return true;
    }
    
    return false;
}

// scade ttl-ul cu 1 si updateaza checksum-ul (incremental yay)
int update_ttl_checksum(packet* m) {
    struct iphdr *ip_hdr = (struct iphdr *)(m->payload + IP_OFF);

    if (ip_hdr->protocol == IPPROTO_ICMP) {
        if (!is_icmp_checksum_good(*m)) {
            return 3;
            // nu e checksum bun, il "aruncam"
        }
    }

    if (!is_ip_checksum_good(ip_hdr)) {
        return 1;
        // nu e checksum bun, il "aruncam"
    }
    
    if (ip_hdr->ttl <= 1) {
        return 2;
    }

    uint16_t incremental_check = incremental_checksum(ip_hdr->ttl, ip_hdr->check);
    ip_hdr->ttl = ip_hdr->ttl - 1;
    ip_hdr->check = incremental_check;

    return 0;
}

// sincer formula din RFC1624 era prea overkill, am luat-o pe foaie in cazul
// ttl-ului si am gasit formula asta mai usoara
uint16_t incremental_checksum(uint8_t old_ttl_n, uint16_t old_checksum) {
    uint16_t new_checksum = ~(~old_checksum - 1);
    return new_checksum;
}

// functia asta trimite raspuns la icmp echo request
void handle_icmp_echo(packet *m, struct in_addr router_ip) {
    struct ether_header *eth_hdr = (struct ether_header *)m->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + IP_OFF);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + ICMP_OFF);
    // icmp
    icmp_hdr->type = 0;
    icmp_hdr->code = 0;
    // ip
    ip_hdr->daddr = ip_hdr->saddr;
    ip_hdr->saddr = htonl(router_ip.s_addr);
    ip_hdr->check = 0;
    ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));
    // eth
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, 6);
    get_interface_mac(m->interface, eth_hdr->ether_shost);
    // final checksum
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = ip_checksum(m->payload + ICMP_OFF, m->len - ICMP_OFF);
}

int is_for_router(packet *m, struct in_addr interface_ip[4], arp_entry* arp_table, queue q) {
    struct ether_header *eth_hdr = (struct ether_header *)m->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + IP_OFF);

    // daca am primit un pachet arp, sigur este pt noi
    if (eth_hdr->ether_type == htons(0x0806)) {
        struct ether_arp *arp_hdr = (struct ether_arp*)(m->payload + sizeof(struct ether_header));
        
        // am primit un arp request destinat routerului
        if (arp_hdr->arp_op == htons(ARPOP_REQUEST)) {
            send_arp_reply(m);
        } else {
            memorise_arp(*m, arp_table, q);
        }

        return 1;
    }

    // verificam daca pachetul e pt ip-ul nostru
    if (ip_hdr->daddr == htonl(interface_ip[m->interface].s_addr)) {
        if ((eth_hdr->ether_type == htons(0x0800)) && (ip_hdr->protocol == IPPROTO_ICMP)) {
            // am primit pachet icmp, si asta poate sa fie doar echo request
            handle_icmp_echo(m, interface_ip[m->interface]);
            return 2;
        }
    }

    return 0;
}

// initializeaza partea pachetului icmp comuna (intre time exceeded si destination unreachable)
packet* init_icmp(packet *old) {
    packet* m = calloc(1, sizeof(packet));
    m->interface = old->interface;
    m->len = sizeof(struct iphdr) + sizeof(struct ether_header) + sizeof(struct icmphdr);

    struct ether_header *eth_hdr = (struct ether_header *)m->payload;
	struct iphdr *ip_hdr = (struct iphdr *)(m->payload + IP_OFF);
    struct iphdr *old_ip_hdr = (struct iphdr *)(old->payload + IP_OFF);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + ICMP_OFF);

    // eth hdr
    eth_hdr->ether_type = htons(0x0800);
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t) * 6);
    get_interface_mac(m->interface, eth_hdr->ether_shost);

    // ip_hdr
    inet_aton(get_interface_ip(m->interface), &temp);

    ip_hdr->version = 4;
    ip_hdr->id = 0;
    ip_hdr->frag_off = 0;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    ip_hdr->daddr = old_ip_hdr->saddr;
    ip_hdr->saddr = temp.s_addr;
    ip_hdr->ttl = 69;
    ip_hdr->protocol = IPPROTO_ICMP;
    ip_hdr->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
    ip_hdr->check = 0;
    ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

    // type si code nu le setez acum
    icmp_hdr->checksum = 0;

    return m;
}

// completam type, code si checksum, adica ce ne-a mai ramas dupa init_icmp
packet* icmp_timeout(packet *m) {
    m = init_icmp(m);

    struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + ICMP_OFF);

    icmp_hdr->type = ICMP_TIME_EXCEEDED;
    icmp_hdr->code = 0;

    icmp_hdr->checksum = ip_checksum(m->payload + ICMP_OFF, m->len - ICMP_OFF);
    return m;
}

// completam type, code si checksum, adica ce ne-a mai ramas dupa init_icmp
packet* icmp_host_unreachable(packet *m) {
    m = init_icmp(m);

    struct icmphdr *icmp_hdr = (struct icmphdr *)(m->payload + ICMP_OFF);

    icmp_hdr->type = ICMP_DEST_UNREACH;
    icmp_hdr->code = 0;

    icmp_hdr->checksum = ip_checksum(m->payload + ICMP_OFF, m->len - ICMP_OFF);
    return m;
}

// wrapper peste send, care trimite arp request daca nu avem macul
void try_to_send(packet* m, arp_entry* table, routing_node node, queue q) {
    struct ether_header *eth_hdr = (struct ether_header *)m->payload;
    uint8_t* dest_mac = get_mac(table, inet_network(node.next_hop));
    
    if (dest_mac == null) {
        packet* temp = calloc(1, sizeof(packet));
        memcpy(temp, m, sizeof(packet));
        queue_enq(q, temp);
        send_arp_request(*m);
    } else {
        memcpy(eth_hdr->ether_dhost, dest_mac, sizeof(uint8_t) * 6);
        get_interface_mac(m->interface, eth_hdr->ether_shost);
        send_packet(m->interface, m);
    }
}

int main(int argc, char *argv[]) {
    setvbuf(stdout, null, _IONBF, 0) ;
    packet m;
    int rc;
    // initializari
    init();
    root = parse_routing_table();
    arp_entry* arp_table = init_arp();
    queue q = queue_create();
    // ne tinem, pentru comoditate, adresele ip ale interfetelor
    struct in_addr* interface_ip = calloc(4, sizeof(struct in_addr));
    for (int i = 0; i < 4; i++) {
        parse_address(get_interface_ip(i), &interface_ip[i]);
    }
    
    while (1) {
        rc = get_packet(&m);
        struct ether_header *eth_hdr = (struct ether_header *)m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + IP_OFF);

        DIE(rc < 0, "get_message");
        // daca nu avem un pachet valid
        if (eth_hdr->ether_type != htons(0x0800) && eth_hdr->ether_type != htons(0x0806)) {
            continue;
        }

        int err = 0;
        // aici verificam integritatea pachetului
        if (eth_hdr->ether_type == htons(0x0800)) {
            err = update_ttl_checksum(&m);
        }

        if (err == 1) { // nu e checksum-ul bun
            continue;
        }

        if (err == 3) { // nu e checksum-ul icmp-ului bun
            continue;
        }

        if (err == 2) { // ttl <= 1
            m = *icmp_timeout(&m);
            send_packet(m.interface, &m);
            continue;
        }

        routing_node* node;
        int for_router = is_for_router(&m, interface_ip, arp_table, q);
        // daca nu este pentru router sau e icmp echo request
        if (for_router == NOT_FOR_FOUTER || for_router == ICMP_PACKET) {
            temp.s_addr = ip_hdr->daddr;
            node = search_routing_table(root, ntohl(ip_hdr->daddr));
            
            if (node == null) { // daca nu am gasit in routing table
                m = *icmp_host_unreachable(&m);
                send_packet(m.interface, &m);
                continue;
            }

            m.interface = node->interface;
            try_to_send(&m, arp_table, *node, q);
        }
    }
}
