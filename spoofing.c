#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <netdb.h>



//CHECKSUM
unsigned short chksum(unsigned short *addr, int length){
    int count = length;
    int s = 0;
    unsigned short *address = addr;
    unsigned short total = 0;
    while (count > 1) {
        s += *address++;
        count -= 2;
    }

    if(count == 1){
        *(unsigned char*) (&total) = *(unsigned char*)address;
        s += total;
    }

    s = (s >> 16) + (s & 0xFFFF);
    s += (s >> 16);
    total = ~s;
    return(total);
}

int main(int argc, char **argv){
    struct icmp icmp;
    struct ip ip;
    struct udphdr udp;
    int sd;
    const int check = 1;
    struct sockaddr_in socketInput;

    u_char* packet;
    packet = (u_char *)malloc(100);
    
    //setting icmp struct values
    icmp.icmp_type = ICMP_ECHO;
    icmp.icmp_code = 0;
    icmp.icmp_id = htons(4444);
    icmp.icmp_seq = htons(0x0);
    icmp.icmp_cksum = htons(0x4455);

    //setting ip struct values
    ip.ip_hl = 0x5;
    ip.ip_v = 0x4;
    ip.ip_tos = 0x0;
    ip.ip_len = 100;
    ip.ip_id = 0;
    ip.ip_off = 0x0;
    ip.ip_ttl = 64;
    ip.ip_p = IPPROTO_ICMP;
    ip.ip_sum = chksum((unsigned short *)&ip, sizeof(ip));



    //SOURCE IP ADDRESS **************************************************** SOURCE IP ADDRESS
    ip.ip_src.s_addr = inet_addr("104.198.102.93");

    //DESTINATION IP ADDRESS *********************************************** DESTINATION IP ADDRESS
    ip.ip_dst.s_addr = inet_addr("208.65.153.238");
    
    memcpy(packet, &ip, sizeof(ip));
    
    memcpy(packet + 20, &icmp, 8);
    
    //putting the packet to the network
    if((sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0){
        perror("raw socket");
        exit(1);
    }

    if(setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &check, sizeof(check)) < 0){
        perror("setsockopt");
        exit(1);
    }
    
    memset(&socketInput, 0, sizeof(socketInput));
    socketInput.sin_family = AF_INET;
    socketInput.sin_addr.s_addr = ip.ip_dst.s_addr;
    
    if(sendto(sd, packet, ip.ip_len, 0, (struct sockaddr *)&socketInput,
        sizeof(struct sockaddr)) < 0){
        perror("sendto"); exit(1);
    }
}