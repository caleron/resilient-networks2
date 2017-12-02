#include <iostream>
#include <map>
#include <vector>
#include <pcap.h>
#include <pcap/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <list>
#include <set>

using namespace std;

struct UserData {
    // Link type
    int data_link = 0;
    // Basic counting of packets
    unsigned long long int packet_counter = 0;
    // Whatever you need, define it here
    unsigned long long int ipv4_payload = 0;
    set<in_addr_t> found_ips;
    map<uint16_t, int> layer_3_protocol_counter;
    map<uint8_t, int> layer_4_protocol_counter;
    unsigned long long int udp_payload = 0;
    unsigned long long int tcp_payload = 0;
    unsigned long long int total_pcap_captured_bytes = 0;
    unsigned long long int total_pcap_bytes = 0;
};

void increaseCounter(unsigned long long int &counter);

// Prototype that processes every packet
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);


// Main of the programm
int main(int argc, char *argv[]) {

    // Read argument command line
    if (argc != 2 && argc != 3) {
        cout << "Use the file name as first command line argument plus optionally the number of packets to process"
             << endl;
        return 1;
    }
    // File name for the network trace
    const char *file_name = argv[1];
    // Number of packets to process
    int nPackets = 0;
    if (argc == 3) {
        nPackets = atoi(argv[2]);
    }

    // Error buffer
    pcap_t *descr;
    char errbuf[PCAP_ERRBUF_SIZE];

    // UserData to pass when processing packets
    struct UserData userData;

    // open capture file for offline processing
    descr = pcap_open_offline(file_name, errbuf);
    if (descr == NULL) {
        cout << "pcap_open_live() failed: " << errbuf << endl;
        return 1;
    }

    // check the link layer type
    userData.data_link = pcap_datalink(descr);
    if (userData.data_link != DLT_EN10MB) {
        cout << "Cannot process link layer type " << userData.data_link << endl;
        return 1;
    }

    // start packet processing loop, just like live capture
    if (pcap_loop(descr, nPackets, packetHandler, (unsigned char *) &userData) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    // Print statistics
    cout << "Number of pcap observer traffic: " << userData.total_pcap_bytes << endl;
    cout << "Number of bytes pcap actually captured: " << userData.total_pcap_captured_bytes << endl;

    cout << "Number of processed packets: " << userData.packet_counter << endl;

    cout << "Number of different IPv4 addresses: " << to_string(userData.found_ips.size()) << endl;

    cout << "Layer 3 Protocols: " << endl;

    for (auto &it : userData.layer_3_protocol_counter) {
        // some indent
        cout << "  ";
        // switch by all protocols defined in ethernet.h
        switch (it.first) {
            case ETHERTYPE_IP:
                cout << "IP: ";
                break;
            case ETHERTYPE_ARP:
                cout << "ARP: ";
                break;
            case ETHERTYPE_PUP:
                cout << "PUP: ";
                break;
            case ETHERTYPE_SPRITE:
                cout << "Sprite: ";
                break;
            case ETHERTYPE_REVARP:
                cout << "revarp: ";
                break;
            case ETHERTYPE_AT:
                cout << "AT: ";
                break;
            case ETHERTYPE_AARP:
                cout << "AARP:";
                break;
            case ETHERTYPE_VLAN:
                cout << "VLAN: ";
                break;
            case ETHERTYPE_IPX:
                cout << "IPX: ";
                break;
            case ETHERTYPE_IPV6:
                cout << "IPv6: ";
                break;
            case ETHERTYPE_LOOPBACK:
                cout << "loopback: ";
                break;
            default:
                cout << "unknown protocol " << to_string(it.first);
                break;
        }
        // output the number
        cout << to_string(it.second) << endl;
    }

    cout << "Total IPv4 payload: " << to_string(userData.ipv4_payload) << endl;

    cout << "Layer 4 Protocols inside IPv4:" << endl;

    for (auto &it : userData.layer_4_protocol_counter) {
        cout << "  ";
        switch (it.first) {
            case IPPROTO_TCP:
                cout << "TCP";
                break;
            case IPPROTO_UDP:
                cout << "UDP";
                break;
            case IPPROTO_ICMP:
                cout << "ICMP";
                break;
            case IPPROTO_IPV6:
                cout << "IPv6";
                break;
            case IPPROTO_GRE:
                cout << "GRE";
                break;
            case IPPROTO_ESP:
                cout << "ESP";
                break;
            case IPPROTO_AH:
                cout << "AH";
                break;
            default:
                cout << "other " << to_string(it.first);
                break;
        }
        cout << ": " << to_string(it.second) << endl;
    }

    cout << "Total TCP payload bytes: " << to_string(userData.tcp_payload) << endl;
    cout << "Total UDP payload bytes: " << to_string(userData.udp_payload) << endl;

    // Everything comes to an end...
    return 0;
}

void increaseCounter(unsigned long long int &counter) {
    counter++;
}

// ethernet header has always 14 bytes
#define ETHERNET_HEADER_SIZE 14
// udp header has always 8 bytes
#define UDP_HEADER_SIZE 8
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Setup variables
    const struct ether_header *ethernetHeader;

    struct UserData *ud = (struct UserData *) userData;

    increaseCounter(ud->packet_counter);

    // len is length of the original packet
    ud->total_pcap_bytes += pkthdr->len;
    // caplen is the available length in this capture
    ud->total_pcap_captured_bytes += pkthdr->caplen;
    // therefore use len - headersize to determine real payload sizes

    // Get Link Header (layer 2)
    ethernetHeader = (struct ether_header *) packet;
    // the size of the contained packet is the total size of the packet reduced by the ethernet header size
    u_int contained_packet_length = pkthdr->len - ETHERNET_HEADER_SIZE;

    uint16_t protocol = ntohs(ethernetHeader->ether_type);

    if (ud->layer_3_protocol_counter.find(protocol) == ud->layer_3_protocol_counter.end()) {
        // protocol is not in the map, set to 1
        ud->layer_3_protocol_counter[protocol] = 1;
    } else {
        ud->layer_3_protocol_counter[protocol]++;
    }

    if (protocol == ETHERTYPE_IP) {
        const struct ip *ip;
        // ip packet begins after ethernet header
        ip = (struct ip *) (packet + ETHERNET_HEADER_SIZE);

        // only handle IPv4
        if (ip->ip_v == 4) {
            // length of the whole ip packet, does not match with the contained_packet_length somehow
            uint16_t ip_packet_length = ntohs(ip->ip_len);

            // add the ips to the set (note: is ignored if already in the set, a set ignores duplicate values)
            ud->found_ips.insert(ip->ip_src.s_addr);
            ud->found_ips.insert(ip->ip_dst.s_addr);

            // the header length fields denotes the length in blocks of 32 bit = 4 byte
            unsigned int ip_header_size = ip->ip_hl * 4;
            // payload should be the total packet size minus the header size
            unsigned int ip_packet_payload_length = contained_packet_length - ip_header_size;
            ud->ipv4_payload += ip_packet_payload_length;

            // count the layer 4 protocols inside IPv4
            if (ud->layer_4_protocol_counter.find(ip->ip_p) == ud->layer_4_protocol_counter.end()) {
                // protocol is not in the map, set to 1
                ud->layer_4_protocol_counter[ip->ip_p] = 1;
            } else {
                ud->layer_4_protocol_counter[ip->ip_p]++;
            }

            if (ip->ip_p == IPPROTO_TCP) {
                const struct tcphdr *tcp_header;
                // ip payload should start directly after ip header
                tcp_header = (struct tcphdr *) (packet + ETHERNET_HEADER_SIZE + ip->ip_hl);
                // th_off is the header size in blocks of 32 bits (= 4byte)
                int tcp_header_size = tcp_header->th_off * 4;

                // this payload is about 895 trillion ... way too big ... idk why
                ud->tcp_payload += ip_packet_payload_length - tcp_header_size;
                if (ip_packet_payload_length > 2000) {
                    cout << "huge package" << endl;
                }
                if (ip_packet_payload_length - tcp_header_size < 0) {
                    cout << "no tcp payload??";
                }
            } else if (ip->ip_p == IPPROTO_UDP) {
                const struct udphdr *udp_header;
                // ip payload should start directly after ip header
                udp_header = (struct udphdr *) (packet + ETHERNET_HEADER_SIZE + ip->ip_hl);

                // udp payload is total length minus header length
                ud->udp_payload += ip_packet_payload_length - UDP_HEADER_SIZE;
            }

            // just for security check - remove later
            if (ip_packet_payload_length <= 0) {
                cout << "no payload ???" << endl;
            }
        } else {
            // does never happen, remove in final version
            cout << "IP packet was not IPv4!!!" << endl;
        }
    }
}

