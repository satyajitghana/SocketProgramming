#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>    /* tcp header */
#include <netinet/ip.h>     /* ip header */
#include <arpa/inet.h>

/*
 * Creating RAW TCP Packets
 * Author : shadowleaf (Satyajit Ghana)
 *
 * */

/* 12 Bytes pseudo header needed for tcp header checksum calculation */

struct pseudo_header {
    u_int32_t   source_address;
    u_int32_t   dest_address;
    u_int8_t    placeholder;
    u_int8_t    protocol;
    u_int8_t    tcp_length;
};

/* generic checksum calculation function */
unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register unsigned short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*) ptr;
        sum += oddbyte;
    }

    sum = (sum>>16) + (sum & 0xffff);
    sum = sum + (sum>>16);
    answer = (unsigned short)~sum;

    return answer;
}

int main() {
    /* create a raw socket */
    int sock;
    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_TCP)) == -1) {
        perror("Failed to create the socket ");
        exit(1);
    } else  {
        printf("Socket created Successfully \n");
    }

    /* datagram to represent the packet */
    char datagram[4096], source_ip[32], *data, *pseudogram;

    /* zero out the packer buffer */
    memset(datagram, 0, 4096);

    /* IP header */
    struct iphdr *iph = (struct iphdr *)datagram;

    /* TCP header */
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;

    /* data part */
    data = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, "Heyyyyy there Hello Internet !");

    /* address resolution : do the spoofing here */
    strcpy(source_ip, "192.168.17.135");
    sin.sin_family = AF_INET;
    sin.sin_port = htons(80);
    sin.sin_addr.s_addr = inet_addr("1.1.1.1");

    /* fill in the IP header */
    iph -> ihl = 5;
    iph -> version = 4;
    iph -> tos = 0;
    iph -> tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data);
    iph -> id = (u_int16_t)htonl(54321); /* ID of this packet */
    iph -> frag_off = 0;
    iph -> ttl = 255;
    iph -> protocol = IPPROTO_TCP;
    iph -> check = 0;
    iph -> saddr = inet_addr(source_ip);
    iph -> daddr = sin.sin_addr.s_addr;

    /* IP checksum */
    iph -> check = csum((unsigned short int *)datagram, iph -> tot_len);

    /* fill in the TCP header */
    tcph -> source = htons(1234);
    tcph -> dest = htons(80);
    tcph -> seq = 0;
    tcph -> ack_seq = 0;
    tcph -> doff = 5;
    tcph -> fin = 0;
    tcph -> rst = 0;
    tcph -> psh = 0;
    tcph -> ack = 0;
    tcph -> urg = 0;
    tcph -> window = htons(5840);
    tcph -> check = 0;
    tcph -> urg_ptr = 0;

    /* TCP checksum */
    psh.source_address = inet_addr(source_ip);
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = (u_int8_t)htons(sizeof(struct tcphdr) + strlen(data));

    /* packet size */
    size_t psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + strlen(data);
    pseudogram = malloc(psize);

    memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + strlen(data));

    tcph -> check = csum((unsigned short *) pseudogram, (int)psize);

    int one = 1;
    const int *val = &one;

    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL ");
        exit(0);
    }

    /* loop to flood */
    while(1) {
        /* send the packet */
        if (sendto(sock, datagram, iph -> tot_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            perror("sendto failed ");
        } else {
            printf("packet sent. length : %d \n", iph -> tot_len);
        }

        sleep(1);
    }

    return 0;
}