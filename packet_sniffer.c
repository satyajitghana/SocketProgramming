//
// Created by shadowleaf on 29-Dec-18.
//

#include "packet_sniffer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int start_sniff() {
    struct sockaddr_in source_socket_address, dest_socket_address;

    int packet_size;

    unsigned char* buffer = malloc(65536);

    /* open the raw socket */
    int sock;
    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_UDP)) == -1) {
        perror("Failed to create the socket ");
        exit(1);
    }

    while(1) {
        packet_size = recvfrom(sock , buffer , 65536 , 0 , NULL, NULL);
        if (packet_size == -1) {
            printf("Failed to get packets\n");
            return 1;
        }

        struct iphdr *ip_packet = (struct iphdr *)buffer;

        memset(&source_socket_address, 0, sizeof(source_socket_address));
        source_socket_address.sin_addr.s_addr = ip_packet->saddr;
        memset(&dest_socket_address, 0, sizeof(dest_socket_address));
        dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

        printf("Incoming Packet: \n");
        printf("Packet Size (bytes): %d\n",ntohs(ip_packet->tot_len));
        printf("Source Address: %s\n", inet_ntoa(source_socket_address.sin_addr));
        printf("Destination Address: %s\n", inet_ntoa(dest_socket_address.sin_addr));
        printf("Identification: %d\n\n", ntohs(ip_packet->id));
    }
}