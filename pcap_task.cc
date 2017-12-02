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
    map<uint16_t, int> protocol_counter;
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
    cout << "Number of processed packets: " << userData.packet_counter << endl;

    cout << "Number of different IPv4 addresses: " << to_string(userData.found_ips.size()) << endl;

    cout << "Protocols: " << endl;

    for (auto &it : userData.protocol_counter) {
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

    // Everything comes to an end...
    return 0;
}

void increaseCounter(unsigned long long int &counter) {
    counter++;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Setup variables
    const struct ether_header *ethernetHeader;

    struct UserData *ud = (struct UserData *) userData;

    increaseCounter(ud->packet_counter);

    // Get Link Header (layer 2)
    ethernetHeader = (struct ether_header *) packet;
    // the size of the contained packet is the total size of the packet reduced by the ethernet header size
    u_int contained_packet_length = pkthdr->len - sizeof(struct ether_header);

    uint16_t protocol = ntohs(ethernetHeader->ether_type);

    if (ud->protocol_counter.find(protocol) == ud->protocol_counter.end()) {
        // protocol is not in the map, set to 1
        ud->protocol_counter[protocol] = 1;
    } else {
        ud->protocol_counter[protocol]++;
    }

    if (protocol == ETHERTYPE_IP) {
        const struct ip *ip;
        // ip packet begins after ethernet header
        ip = (struct ip *) (packet + sizeof(struct ether_header));

        // only handle IPv4
        if (ip->ip_v == 4) {
            // length of the whole ip packet, does not match with the contained_packet_length somehow
            uint16_t ip_packet_length = ntohs(ip->ip_len);

            // add the ips to the set (note: is ignored if already in the set, a set ignores duplicate values)
            ud->found_ips.insert(ip->ip_src.s_addr);
            ud->found_ips.insert(ip->ip_dst.s_addr);

            // payload should be the total packet size minus the header
            ud->ipv4_payload += ip_packet_length - ip->ip_hl;

            // just for security check - remove later
            if (ip_packet_length - ip->ip_hl <= 0) {
                cout << "no payload ???" << endl;
            }

            // just for demonstration how to get a readable address
            if (ud->packet_counter < 10) {
                cout << ip->ip_v << " - ";
                cout << inet_ntoa(ip->ip_src) << " - ";
                cout << ntohs(ip->ip_len) << " - ";
                cout << inet_ntoa(ip->ip_dst) << endl;
            }
        } else {
            // does never happen, remove in final version
            cout << "IP packet was not IPv4!!!" << endl;
        }
    }
}

