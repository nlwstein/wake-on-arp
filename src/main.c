#include <errno.h>
#include <netdb.h>
#include <stdio.h>		// for standard things
#include <stdlib.h>		// malloc
#include <string.h>		// strlen
#include <stdbool.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>				// provides declarations for ip header
#include <netinet/if_ether.h>		// for ETH_P_ALL
#include <net/ethernet.h>			// for ether_header
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <byteswap.h>

#include "ns_arp.h"
#include "ns_arp_packet.h"

#include "array.h"
#include "functions.h"

#ifndef CONFIG_PREFIX
	#error "Please specify CONFIG_PREFIX (usually /etc on Linux)"
#endif

// RETurn ON FAILure
#define RETONFAIL(x) { int a = x; if(a) return a; }

// FAILure ON ARGumentS
#define FAILONARGS(i, max) { if(max==i+1) { \
				fprintf(stderr, "Invalid number of arguments!\n"); \
				return -1; } }

const char *USAGE_INFO = \
"This program is a daemon wakes up a device on the local\n"
"network based upon if the local system tries to access it\n"
"via LAN network.\n"
"These parameters can also be set in the config file,\n"
"which is located at "CONFIG_PREFIX"/wake-on-arp.conf\n"
"Usage:\n"
"\t-h/--help - this screen\n"
"\t-i - IP address of device to wake up\n"
"\t-m - MAC (hardware) address of device to wake up\n"
"\t-d - network device to check traffic from (eg. eth0)\n"
"\t-b - broadcast IP address (eg. 192.168.1.255)\n"
"\t-s - subnet IP mask (eg. 24)\n"
"\t-ag - send magic packet even if the ARP came from the router/gateway (disabled by default).\n"
"\t--allow-any-source - allow ARP requests from any source IP (default: false)\n"
"\t--allow-source <ip> - allow ARP requests only from this source IP (can be specified multiple times)\n"
"\t--deny-source <ip> - deny ARP requests from this source IP (can be specified multiple times)\n"
"\t--debug - enable debug logging\n"
"For further info look here: https://github.com/nikp123/wake-on-arp/issues/1#issuecomment-882708765\n";

void cleanup();
void sig_handler();
int initialize();
int watch_packets();
int process_packet(unsigned char*);
int parse_arp(unsigned char *);
int parse_ethhdr(unsigned char*);
int get_local_ip();
int send_magic_packet(unsigned char*);

struct main {
	char **allow_hostnames;
	uint32_t *allow_host_ips;
	int allow_host_refresh;
	time_t allow_host_last_refresh;
	bool debug;
	char *eth_dev_s;
	char *eth_ip_s;
	char *broadcast_ip_s;
	char *subnet_s;
	char *allow_gateway_s;

	struct target *target_list;

	uint32_t *source_blacklist;
	uint32_t *source_allowlist;
	uint32_t *source_denylist;
	bool allow_any_source;

	unsigned char eth_ip[4];
	unsigned char gate_ip[4];

	unsigned int  subnet;

	unsigned char *buffer;
	int sock_raw;
	bool alive;
} m;

void cleanup() {
	arr_free(m.source_blacklist);
	targets_destroy(m.target_list);
	close(m.sock_raw);
	free(m.buffer);
}

// handle signals, such as CTRL-C
void sig_handler() {
	m.alive = false;
}

int initialize() {
	RETONFAIL(get_local_ip());

	// get gateway ipv4 :)
	RETONFAIL(get_gateway_ip((unsigned char*)&m.gate_ip, m.eth_dev_s));

	// attach signal handler
	struct sigaction action;
	memset(&action, 0, sizeof(action));
	action.sa_handler = &sig_handler;
	sigaction(SIGINT, &action, NULL);  // close by CTRL-C
	sigaction(SIGTERM, &action, NULL); // close by task manager and/or kill

	// set alive flag
	m.alive = true;

	// allocate memory for storing packets
	m.buffer = (unsigned char *) malloc(65536);


       // open the socket
       m.sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
       if(m.sock_raw < 0) {
	       perror("socket error");
	       return 1;
       }

       // listen on a specific network device
       int bind_result = setsockopt(m.sock_raw, SOL_SOCKET, SO_BINDTODEVICE, m.eth_dev_s, strlen(m.eth_dev_s)+1);
       if(bind_result < 0) {
	       perror("setsockopt SO_BINDTODEVICE failed");
	       close(m.sock_raw);
	       return 1;
       }

	uint32_t eth_ip =     *((uint32_t*)&m.eth_ip);
	uint32_t gateway_ip = *((uint32_t*)&m.gate_ip);

	// add gateway to blacklist if needed
	bool allow_gateway = false;
	if(m.allow_gateway_s) {
		allow_gateway = the_great_bool_destringifier(m.allow_gateway_s);
	}

	if(!allow_gateway) {
		arr_add(m.source_blacklist, gateway_ip);
	}

	printf("Listen for ARP requests from Source IPs ");
	print_ip(eth_ip&m.subnet);
	printf(" - ");
	print_ip(eth_ip|~m.subnet);
	if(arr_count(m.source_blacklist) != 0) {
		printf(" but ignore the following IP(s):");

		for(size_t i = 0; i < arr_count(m.source_blacklist); i++) {
			printf(" ");
			print_ip(m.source_blacklist[i]);
		}
	}
	puts("");
	fflush(stdout); //to see this message in systemctl status

	return 0;
}

int watch_packets() {
	int saddr_size, data_size;
	struct sockaddr saddr;

	while(m.alive) {
		saddr_size = sizeof saddr;
		// receive a packet
		data_size = recvfrom(m.sock_raw, m.buffer, 65536, 0, &saddr, (socklen_t*)&saddr_size);
		if(data_size < 0) {
			if(!m.alive) {
				return 0; //don't print errors for stop
			}
			perror("recvfrom failed to get packets");
			return 1;
		}
		// now process the packet
		RETONFAIL(process_packet(m.buffer));
	}
	return 0;
}

int process_packet(unsigned char* buffer) {
	// get the IP Header part of this packet, excluding the ethernet header
	//struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));

	// TODO: Research packet types for ARP
	// Known types are: 157 (from router), 87 and 129
	//printf("%u\n", iph->protocol);

	// for now, accept all packets
	RETONFAIL(parse_ethhdr(buffer));

	return 0;
}

int parse_arp(unsigned char *data) {
	ns_arp_packet_hdr_t *arp_hdr = (ns_arp_packet_hdr_t *) data;
	ns_arp_IPv4_eth_packet_t *arp_IPv4 = NULL;

	if(ntohs(arp_hdr->ns_arp_hw_type) != NS_ARP_ETHERNET_TYPE) {
		fprintf(stderr, "dis not ethernet :(\n");
		exit(EXIT_FAILURE);
	}

	if(ntohs(arp_hdr->ns_arp_proto_type) != NS_ETH_TYPE_IPv4) {
		fprintf(stderr, "i bet you're using IPv4\n");
		exit(EXIT_FAILURE);
	}

	arp_IPv4 = (ns_arp_IPv4_eth_packet_t *) data;

	// sender and target hardware
	//unsigned char *sh = arp_IPv4->ns_arp_sender_hw_addr;
	//unsigned char *th = arp_IPv4->ns_arp_sender_hw_addr;

	// ARP type
	uint16_t type = ntohs(arp_IPv4->ns_arp_hdr.ns_arp_opcode);

       if(type == NS_ARP_REQUEST) {
	       // Log every ARP request received
	       unsigned int src_ip, ta_ip;
	       memcpy(&src_ip, arp_IPv4->ns_arp_sender_proto_addr, sizeof(unsigned int));
	       memcpy(&ta_ip, arp_IPv4->ns_arp_target_proto_addr, sizeof(unsigned int));
	       printf("[DEBUG] ARP request: source IP '");
	       print_ip(src_ip);
	       printf("' target IP '");
	       print_ip(ta_ip);
	       puts("'");
	       fflush(stdout);

	       for(size_t i = 0; i < arr_count(m.target_list); i++) {
		       struct target *link = &m.target_list[i];
		       if(*(unsigned int*)link->ip != ta_ip)
			       continue;

		       // Denylist check
		       int deny_found = -1;
		       arr_find(m.source_denylist, src_ip, &deny_found);
		       if(deny_found > -1) {
			       printf("[DEBUG] Source IP denied: ");
			       print_ip(src_ip);
			       puts("");
			       break;
		       }

		       // Allowlist check
		       if(arr_count(m.source_allowlist) > 0) {
			       int allow_found = -1;
			       arr_find(m.source_allowlist, src_ip, &allow_found);
			       if(allow_found == -1) {
				       printf("[DEBUG] Source IP not in allowlist: ");
				       print_ip(src_ip);
				       puts("");
				       break;
			       }
		       }

		       // allow_any_source overrides subnet/blacklist logic
		       if(m.allow_any_source || ( ((*((unsigned int*)&m.eth_ip))&m.subnet) == (src_ip&m.subnet) )) {
			       int blacklist_found = -1;
			       arr_find(m.source_blacklist, src_ip, &blacklist_found);
			       if(blacklist_found > -1) {
				       #ifdef DEBUG
				       printf("Blocked '");
				       print_ip(src_ip);
				       puts("' from the blacklist!");
				       #endif
				       break;
			       }
			       RETONFAIL(send_magic_packet(link->magic));
			       printf("Magic packet to '");
			       print_ip(ta_ip);
			       printf("' sent by '");
			       print_ip(src_ip);
			       puts("'");
			       fflush(stdout);
		       } else {
			       printf("[DEBUG] ARP request for target IP '");
			       print_ip(ta_ip);
			       printf("' from source IP '");
			       print_ip(src_ip);
			       puts("' (host unreachable, no magic packet sent)");
			       fflush(stdout);
		       }
		       break;
	       }
       }
	return 0;
}

int parse_ethhdr(unsigned char* buffer) {
	struct ethhdr *eth = (struct ethhdr *)buffer;

	// convert network-endianess to native endianess
	unsigned short eth_protocol = ntohs(eth->h_proto);

	if(eth_protocol == 0x0806) {
		unsigned char* arphdr = buffer + sizeof(struct ethhdr);
		RETONFAIL(parse_arp(arphdr));
	}
	return 0;
}

int read_args(int argc, char *argv[]) {
       m.debug = false;
       for(int i=1; i<argc; i++) {
	       if(!strcmp(argv[i], "--debug")) {
		       m.debug = true;
	       }
       }
	arr_init(m.source_allowlist);
	arr_init(m.source_denylist);
	m.allow_any_source = false;
       // Parse allow/deny/any-source options
       for(int i=1; i<argc; i++) {
	       if(!strcmp(argv[i], "--allow-any-source")) {
		       m.allow_any_source = true;
	       } else if(!strcmp(argv[i], "--allow-source")) {
		       FAILONARGS(i, argc);
		       uint8_t address[4];
		       int err = sscanf(argv[i+1], "%hhu.%hhu.%hhu.%hhu",
			       &address[0], &address[1], &address[2], &address[3]);
		       if(err != 4) {
			       fprintf(stderr, "Invalid IP address for --allow-source: %s\n", argv[i+1]);
			       return -1;
		       }
		       uint32_t address_ptr = *((uint32_t*)&address);
		       arr_add(m.source_allowlist, address_ptr);
		       i++;
	       } else if(!strcmp(argv[i], "--deny-source")) {
		       FAILONARGS(i, argc);
		       uint8_t address[4];
		       int err = sscanf(argv[i+1], "%hhu.%hhu.%hhu.%hhu",
			       &address[0], &address[1], &address[2], &address[3]);
		       if(err != 4) {
			       fprintf(stderr, "Invalid IP address for --deny-source: %s\n", argv[i+1]);
			       return -1;
		       }
		       uint32_t address_ptr = *((uint32_t*)&address);
		       arr_add(m.source_denylist, address_ptr);
		       i++;
	       }
       }
	for(int i=1; i<argc; i++) {
		if(!strcmp(argv[i], "-h")||!strcmp(argv[i], "--help")) {
			puts(USAGE_INFO);
			return 0;
		} else if(!strcmp(argv[i], "-i")) {
			FAILONARGS(i, argc);
			target_ip_add(m.target_list, 0, strdup(argv[i+1]));
			i++;
		} else if(!strcmp(argv[i], "-m")) {
			FAILONARGS(i, argc);
			target_mac_add(m.target_list, 0, strdup(argv[i+1]));
			i++;
		} else if(!strcmp(argv[i], "-d")) {
			FAILONARGS(i, argc);
			m.eth_dev_s = argv[i+1];
			i++;
		} else if(!strcmp(argv[i], "-b")) {
			FAILONARGS(i, argc);
			m.broadcast_ip_s = argv[i+1];
			i++;
		} else if(!strcmp(argv[i], "-s")) {
			FAILONARGS(i, argc);
			m.subnet_s = argv[i+1];
			i++;
		} else if(!strcmp(argv[i], "-ag")) {
			m.allow_gateway_s = "true";
		}
	}
	return 0;
}

int parse_args() {
	if(!m.eth_dev_s) {
		fprintf(stderr, "Ethernet device to record traffic from not specified!\n");
		return 1;
	}
	if(!m.broadcast_ip_s) {
		fprintf(stderr, "Broadcast IP not specified!\n");
		return 1;
	}
	if(!m.subnet_s) {
		printf("No search subnet provided. Assuming default host IP must match ARP request.\n");
		m.subnet = 0xffffffff;
	}

	// create target macs, ips and magic packets
	RETONFAIL(targets_configure(m.target_list));

	// subnet mask
	if(m.subnet_s) {
		int mask_value;
		int error = sscanf(m.subnet_s, "%d", &mask_value);
		if(error != 1 || mask_value < 0 || mask_value > 31) {
			fprintf(stderr, "Error: Subnet mask must be a value between 0 and 31\n");
		}

		// calculate proper net mask
		unsigned int subnet_bigendian = 0xffffffff << (32-mask_value);
		m.subnet = __builtin_bswap32(subnet_bigendian);
	}

	return 0;
}

int send_magic_packet(unsigned char *magic_packet) {
	int udpSocket = 1;
	int broadcast = 1;
	struct sockaddr_in udpClient, udpServer;

	// setup broadcast socket
	udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
	if(setsockopt(udpSocket, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof(broadcast)) == -1) {
		perror("socket error");
		return 1;
	}

	// set parameters
	udpClient.sin_family = AF_INET;
	udpClient.sin_addr.s_addr = INADDR_ANY;
	udpClient.sin_port = 0;

	// bind socket
	bind(udpSocket, (struct sockaddr*) &udpClient, sizeof(udpClient));

	// set server end point (the broadcast address)
	udpServer.sin_family = AF_INET;
	udpServer.sin_addr.s_addr = inet_addr(m.broadcast_ip_s);
	udpServer.sin_port = htons(9);

	// set server end point
	sendto(udpSocket, magic_packet, sizeof(unsigned char)*102, 0, (struct sockaddr*) &udpServer, sizeof(udpServer));

	// clean after use
	close(udpSocket);

	return 0;
}

int get_local_ip() {
	int fd;
	struct ifreq ifr;

	// open socket
		}
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	if(fd < 0) {
		perror("socket error");
		return 1;
	}

	// get a IPv4 address specifically
	ifr.ifr_addr.sa_family = AF_INET;

				if(m.debug) {
	// get address for the following network device
	strncpy(ifr.ifr_name, m.eth_dev_s, IFNAMSIZ-1);

				}
	// go fetch
	int error = ioctl(fd, SIOCGIFADDR, &ifr);
	if(error == -1) {
		perror("ioctl error");
		return 1;
	}

	// clean up
					if(m.debug) {
	close(fd);

	// get the darn address
					}
	m.eth_ip_s = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);

	// convert IP back to binary
	sscanf(m.eth_ip_s, "%hhu.%hhu.%hhu.%hhu", &m.eth_ip[0],
						&m.eth_ip[1], &m.eth_ip[2], &m.eth_ip[3]);
	return 0;
}
int load_config() {
	arr_init(m.allow_hostnames);
	arr_init(m.allow_host_ips);
	m.allow_host_refresh = 300;
	m.allow_host_last_refresh = 0;

	FILE *fp = fopen(CONFIG_PREFIX"/wake-on-arp.conf", "r");
	if(!fp) {
		fprintf(stderr, "Could not open config file: "CONFIG_PREFIX"/wake-on-arp.conf\n");
		// Still initialize arrays to avoid segfaults
		arr_init(m.source_blacklist);
		arr_init(m.target_list);
		arr_init(m.source_allowlist);
		arr_init(m.source_denylist);
		m.allow_any_source = false;
		return 0; // Not an error, just skip config loading
	}

	// init variables
	arr_init(m.source_blacklist);
	arr_init(m.target_list);
	arr_init(m.source_allowlist);
	arr_init(m.source_denylist);
	m.allow_any_source = false;

	char *line = NULL;
	size_t len;
	while(getline(&line, &len, fp) != -1) {
		char *name, *val;
		int error = sscanf(line, "%ms %ms", &name, &val);
		if(error != 2) {
			if(name) free(name);
			if(val) free(val);
			continue;
		}

		if(!strcmp("broadcast_ip", name)) {
			m.broadcast_ip_s = val;
		} else if(!strcmp("net_device", name)) {
			m.eth_dev_s = val;
		} else if(!strcmp("subnet", name)) {
			m.subnet_s = val;
		} else if(!strcmp("allow_gateway", name)) {
			m.allow_gateway_s = val;
		} else if(!strncmp("target_mac", name, 10)) {
			unsigned int number = 0;
			if(!sscanf(name, "target_mac_%u", &number)) {
				fprintf(stderr, "Invalid option '%s', should be like 'target_mac_1' (fxp)", name);
				return 2;
			}
			target_mac_add(m.target_list, number, val);
		} else if(!strncmp("target_ip", name, 9)) {
			unsigned int number = 0;
			if(!sscanf(name, "target_ip_%u", &number)) {
				fprintf(stderr, "Invalid option '%s', should be like 'target_ip_1' (fxp)", name);
				return 2;
			}
			target_ip_add(m.target_list, number, val);
		} else if(!strcmp("allow_any_source", name)) {
			m.allow_any_source = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
			free(val);
		} else if(!strcmp("source_allow", name)) {
			uint8_t address[4];
			int err = sscanf(val, "%hhu.%hhu.%hhu.%hhu",
				&address[0], &address[1], &address[2], &address[3]);
			if(err != 4) {
				fprintf(stderr, "Invalid IP address specified for allowlist \"%s\"\n", val);
				return 2;
			}
			uint32_t address_ptr = *((uint32_t*)&address);
			arr_add(m.source_allowlist, address_ptr);
			free(val);
		} else if(!strcmp("source_deny", name)) {
			uint8_t address[4];
			int err = sscanf(val, "%hhu.%hhu.%hhu.%hhu",
				&address[0], &address[1], &address[2], &address[3]);
			if(err != 4) {
				fprintf(stderr, "Invalid IP address specified for denylist \"%s\"\n", val);
				return 2;
			}
			uint32_t address_ptr = *((uint32_t*)&address);
			arr_add(m.source_denylist, address_ptr);
			free(val);
		} else if(!strcmp("source_exclude", name)) {
			uint8_t address[4];
			int err = sscanf(val, "%hhu.%hhu.%hhu.%hhu",
				&address[0], &address[1], &address[2], &address[3]);
			if(err != 4) {
				fprintf(stderr, "Invalid IP address specified \"%s\", should be in the following format: \"ab.cd.ef.gh\"\n", val);
				return 2;
			}
			uint32_t address_ptr = *((uint32_t*)&address);
			arr_add(m.source_blacklist, address_ptr);
			free(val);
		} else if(!strcmp("allow_host_refresh", name)) {
			m.allow_host_refresh = atoi(val);
			free(val);
		} else if(!strcmp("allow_host", name)) {
			arr_add(m.allow_hostnames, val);
		} else free(val); // not used

		free(name);
	}
	if(line) free(line);
	// weird seg. fault on ARMv7 (have to investigate)
	//fclose(fp);
	return 0;
}

// Refresh the resolved IPs for allow_hostnames
void refresh_allow_host_ips() {
	// Clear previous IPs
	arr_resize(m.allow_host_ips, 0);
	for(size_t i = 0; i < arr_count(m.allow_hostnames); i++) {
		struct hostent *he = gethostbyname(m.allow_hostnames[i]);
		if(he && he->h_addrtype == AF_INET) {
			for(char **addr = he->h_addr_list; *addr != NULL; addr++) {
				uint32_t ip;
				memcpy(&ip, *addr, sizeof(uint32_t));
				arr_add(m.allow_host_ips, ip);
			}
		}
	}
	m.allow_host_last_refresh = time(NULL);
}
	arr_init(m.source_blacklist);
	arr_init(m.target_list);

	char *line = NULL;
	size_t len;
	while(getline(&line, &len, fp) != -1) {
				}
		char *name, *val;
		int error = sscanf(line, "%ms %ms", &name, &val);
		if(error != 2) continue;

			   if(!strcmp("broadcast_ip", name)) {
	       } else if(!strcmp("allow_any_source", name)) {
		       m.allow_any_source = (strcmp(val, "true") == 0 || strcmp(val, "1") == 0);
	       } else if(!strcmp("source_allow", name)) {
		       uint8_t address[4];
		       int err = sscanf(val, "%hhu.%hhu.%hhu.%hhu",
			       &address[0], &address[1], &address[2], &address[3]);
		       if(err != 4) {
			       fprintf(stderr, "Invalid IP address specified for allowlist \"%s\"\n", val);
			       return 2;
		       }
		       uint32_t address_ptr = *((uint32_t*)&address);
		       arr_add(m.source_allowlist, address_ptr);
		       free(val);
	       } else if(!strcmp("source_deny", name)) {
		       uint8_t address[4];
		       int err = sscanf(val, "%hhu.%hhu.%hhu.%hhu",
			       &address[0], &address[1], &address[2], &address[3]);
		       if(err != 4) {
			       fprintf(stderr, "Invalid IP address specified for denylist \"%s\"\n", val);
			       return 2;
		       }
		       uint32_t address_ptr = *((uint32_t*)&address);
		       arr_add(m.source_denylist, address_ptr);
		       free(val);
			m.broadcast_ip_s = val;
		} else if(!strcmp("net_device", name)) {
			m.eth_dev_s = val;
		} else if(!strcmp("subnet", name)) {
			m.subnet_s = val;
		} else if(!strcmp("allow_gateway", name)) {
			m.allow_gateway_s = val;
		} else if(!strncmp("target_mac", name, 10)) {
			unsigned int number = 0;
			if(!sscanf(name, "target_mac_%u", &number)) {
				fprintf(stderr, "Invalid option '%s', should be like 'target_mac_1' (fxp)", name);
				return 2;
			}
			target_mac_add(m.target_list, number, val);
		} else if(!strncmp("target_ip", name, 9)) {
			unsigned int number = 0;
			if(!sscanf(name, "target_ip_%u", &number)) {
				fprintf(stderr, "Invalid option '%s', should be like 'target_ip_1' (fxp)", name);
				return 2;
			}
			target_ip_add(m.target_list, number, val);
		} else if(!strcmp("source_exclude", name)) {
			uint8_t address[4];
			// assuming IPv4

			int err = sscanf(val, "%hhu.%hhu.%hhu.%hhu",
				&address[0], &address[1], &address[2], &address[3]);

			if(err != 4) {
				fprintf(stderr, "Invalid IP address specified \"%s\", should be"
						" in the following format: \"ab.cd.ef.gh\"\n", val);
				return 2;
			}

			// add 'em
			uint32_t address_ptr = *((uint32_t*)&address);
			arr_add(m.source_blacklist, address_ptr);

			free(val);
		} else free(val); // not used

		// free unused strings
		free(name);
		// WARN: if reload is ever implemented, this is a memory leak
	}
	if(line) free(line);

	// weird seg. fault on ARMv7 (have to investigate)
	//fclose(fp);
	return 0;
}

int main(int argc, char *argv[]) {
	m.allow_gateway_s = NULL; // init config in case it won't be set
	// priority: load_config < read_args
	load_config();
	RETONFAIL(read_args(argc, argv));
	RETONFAIL(parse_args());
	RETONFAIL(initialize());
	RETONFAIL(watch_packets());
	cleanup();
	return 0;
}


