#include "analysis.h" //own definitions

#include "sniff.h" //spinlocks

#include <pcap.h>

#include <netinet/if_ether.h>

#include <netinet/ip.h>

#include <netinet/tcp.h>

#include <signal.h>

#include <stdlib.h>

#include <stdbool.h>

#include <arpa/inet.h>

#include <pthread.h>

/* Initialise global variables 

 */

int arpspoofs = 0;

int xmasscans = 0;

int blacklistedURLs = 0;

unsigned long pcount = 0;

/* Initialise mutexes for the critical section

 */

pthread_mutex_t xmasmutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t arpmutex = PTHREAD_MUTEX_INITIALIZER;

pthread_mutex_t blacklistmutex = PTHREAD_MUTEX_INITIALIZER;

/* Print the intrusion detection report to the screen on Ctrl + C

 */

void report(int signo) {

	if (signo == SIGINT) {		printf("\nIntrusion Detection Report \n");

		printf("%d Xmas packets(s) \n", xmasscans);

		printf("%d possibly malicious gratuitous ARP packets(s) \n", arpspoofs);

		printf("%d URL Blacklist violation(s) \n", blacklistedURLs);

		exit(0);

	}

}

/* Analyse the packet passed in to see if it breaks any rules and if 

   the verbose option is used, print a real time display of offending packets

 */

void analyse(const unsigned char *packet, int verbose) {

	/* Handle the Ctrl + C and pass to the relevant function; report

	 */

	if (signal(SIGINT, report) == SIG_ERR) {

		printf("\ncan't catch SIGINT\n");

	}

	/* Initialise the local structs from the netinet library that will be used

	   to break the packet down

	 */

	struct ether_header *eth_header;

	struct tcphdr *tcp_header;           

	struct ip *ip_header;              

	struct ether_arp *arp_header;   

	unsigned char *payload;            

	u_short d_port;                

	eth_header = (struct ether_header *) packet;

	pcount++;

	/* Handles the packet if it has an IP network layer

	 */

	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) { //if the ethertype of the frame in host byte order is IP

		ip_header = (struct ip *) (packet + sizeof(struct ether_header)); //offet the ip header to the end of the ethernet header

		if (ip_header->ip_p == IPPROTO_TCP) {   //if the higher layer protocol is TCP

			tcp_header = (struct tcphdr *) (packet + sizeof(struct ether_header) + sizeof(struct ip));  //set the TCP header to the offset of the size of the IP header

			if (tcp_header->fin && tcp_header->psh && tcp_header->urg) {  //if the fin, psh and urg flags are present												 

				if (verbose){ dump(eth_header, ip_header, "Xmas packet"); }   //mark the packet as an offending packet

				pthread_mutex_lock(&xmasmutex);    // enter the critical section by locking the mutex from other threads, which may yield the thread if mutex unavailable

				xmasscans++;   //increments the number of xmas scans

				pthread_mutex_unlock(&xmasmutex);   //unlocks the mutex for other threads

			}

			if (ntohs(tcp_header->dest) == 80) {   //if the port is 80 then analyse

				payload = (u_char *)(packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr)); //payload starts at the application data

				if (strstr((u_char *)payload, "www.bbc.co.uk") != NULL) {												 

					if (verbose){ dump(eth_header, ip_header, "HTTP packet containing blacklisted URL"); }

					pthread_mutex_lock(&blacklistmutex); // locks the mutex for other threads; take the mutex itself

					blacklistedURLs++;       //increments the number of blacklisted URL violations

					pthread_mutex_unlock(&blacklistmutex);   //makes the mutex available for other threads

				}

			}

		}

	}

	/* Handles the packet if it has an ARP network layer

	 */

	else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {  //if the ethertype is ARP

		arp_header = (struct ether_arp *) (packet + sizeof(struct ether_header)); //use an ARP header struct on the packet offset from the size of the ethernet header

		if (arp_header->arp_op == htons(ARPOP_REPLY)) {   //if it is a gratuitous ARP packet 										

			if (verbose) { arpdump(eth_header, arp_header); }   // if the verbose option was selected then send the packet off to the display function for ARP packets

			pthread_mutex_lock(&arpmutex);    //locks the mutex for other threads

			arpspoofs++;                     //increments the amount of arp spoofs detected

			pthread_mutex_unlock(&arpmutex);   //unlocks the mutex for other threads to use

		}

	}

}

/* Handles the real time printing of an IP packet if it is detected by the intrusion

   detection system

 */

void dump(struct ether_header *eth_header, struct ip *ip_header, char* reason) {

	unsigned int i;

	printf("\n\n === PACKET %ld ===", pcount);

	printf("\nReason:%s", reason);

	printf("\nSource MAC: ");

	for (i = 0; i < 6; ++i) {

		printf("%02x", eth_header->ether_shost[i]);

		if (i < 5) {

			printf(":");

		}

	}

	printf("\nDestination MAC: ");

	for (i = 0; i < 6; ++i) {

		printf("%02x", eth_header->ether_dhost[i]);

		if (i < 5) {

			printf(":");

		}

	}

	printf("\nSource IP : %s", inet_ntoa(ip_header->ip_src));

	printf("\nDestination IP : %s", inet_ntoa(ip_header->ip_dst));

	printf("\n");

}

/* Handles the real time printing of an ARP packet if it is detected by the intrusion

detection system

*/

void arpdump(struct ether_header *eth_header, struct ether_arp *arp_header) {

	unsigned int i;

	printf("\n\n === PACKET %ld ===", pcount);

	printf("\nReason: gARP packet");

	printf("\nMAC: ");

	for (i = 0; i < 6; ++i) {

		printf("%02x", arp_header->arp_tha[i]);

		if (i < 5) {

			printf(":");

		}

	}

	printf("\nIP Entry: ");

	for (i = 0; i < 4; ++i) {

		printf("%d", arp_header->arp_spa[i]);

		if (i < 3) {

			printf(".");

		}

	}

	printf("\nDestination IP: ");

	for (i = 0; i < 4; ++i) {

		printf("%d", arp_header->arp_tpa[i]);

		if (i < 3) {

			printf(".");

		}

	}

	printf("\n");

}
