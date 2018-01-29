#include <algorithm>
#include <vector>
#include <iostream>
#include <functional>
#include <map>
#include <unordered_map>
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
#include <unordered_set>

using namespace std;
struct Layer4Flow_t;
struct IPv4Flow_t;

struct UserData;

void outputResults1(UserData userData);

string readable_bytes(uint64_t bytes);

struct IPv4Flow_t {
    in_addr source;
    in_addr destination;

    bool const operator==(const IPv4Flow_t &o) const {
        return (source.s_addr == o.source.s_addr && destination.s_addr == o.destination.s_addr)
               || (source.s_addr == o.destination.s_addr && destination.s_addr == o.source.s_addr);
    }

    size_t operator()(const IPv4Flow_t &flow) const {
        return flow.source.s_addr + flow.destination.s_addr;
    }
};

struct Layer4Flow_t {
    in_addr source;
    in_addr destination;
    uint16_t source_port;
    uint16_t destination_port;
    // true for tcp, false for udp
    bool is_tcp;

    bool const operator==(const Layer4Flow_t &o) const {
        return ((source.s_addr == o.source.s_addr && destination.s_addr == o.destination.s_addr &&
                 source_port == o.source_port && destination_port == o.destination_port)
                || (source.s_addr == o.destination.s_addr && destination.s_addr == o.source.s_addr &&
                    source_port == o.destination_port && destination_port == o.source_port))
               && is_tcp == o.is_tcp;
    }

    size_t operator()(const Layer4Flow_t &flow) const {
        return flow.destination.s_addr + flow.source.s_addr + flow.destination_port + flow.source_port + flow.is_tcp;
    }
};

struct TcpHandshake {
    in_addr source;
    in_addr destination;
    uint16_t source_port;
    uint16_t destination_port;
    // sequence number of the syn package from client to server or of the ack package from server to client
    uint32_t seq = 0;

    bool const operator==(const TcpHandshake &o) const {
        return source.s_addr == o.source.s_addr && destination.s_addr == o.destination.s_addr &&
               source_port == o.source_port && destination_port == o.destination_port
               // match with 0 in case of reset flag
               && (o.seq == 0 || seq == 0 || seq == o.seq);
    }

    size_t operator()(const TcpHandshake &s) const {
        return s.destination.s_addr + s.source.s_addr + s.destination_port + s.source_port;
    }

    void swap() {
        in_addr temp = source;
        source = destination;
        destination = temp;
        uint16_t temp1 = source_port;
        source_port = destination_port;
        destination_port = temp1;
    }
};

struct UserData {
    // Link type
    int data_link = 0;
    // Basic counting of packets
    unsigned long long int packet_counter = 0;
    // Whatever you need, define it here
    unsigned long long int ipv4_payload = 0;
    set<in_addr_t> found_ips;
    std::multimap<string, int> found_icmp;
    map<uint16_t, int> layer_3_protocol_counter;
    map<uint8_t, int> layer_4_protocol_counter;
    unsigned long long int udp_payload = 0;
    unsigned long long int tcp_payload = 0;
    unsigned long long int total_pcap_captured_bytes = 0;
    unsigned long long int total_pcap_bytes = 0;
    unordered_map<IPv4Flow_t, uint64_t, IPv4Flow_t> layer_3_flows;
    unordered_map<Layer4Flow_t, uint64_t, Layer4Flow_t> layer_4_flows;
    unordered_set<TcpHandshake, TcpHandshake> tcp_syn;
    unordered_set<TcpHandshake, TcpHandshake> tcp_syn_ack;
};

void increaseCounter(unsigned long long int &counter);

// Prototype that processes every packet
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void packetHandler2(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);

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
    if (userData.data_link != DLT_EN10MB && userData.data_link != DLT_NULL) {
        cout << "Cannot process link layer type " << userData.data_link << endl;
        return 1;
    }

    // start packet processing loop, just like live capture
    void (*handler)(u_char *, const pcap_pkthdr *, const u_char *);
    if (userData.data_link == DLT_EN10MB) {
        handler = packetHandler;
    } else {
        handler = packetHandler2;
    }

    if (pcap_loop(descr, nPackets, handler, (unsigned char *) &userData) < 0) {
        cout << "pcap_loop() failed: " << pcap_geterr(descr);
        return 1;
    }

    if (userData.data_link == DLT_EN10MB) {
        outputResults1(userData);
    } else {

    }

    // Everything comes to an end...
    return 0;
}

void increaseCounter(unsigned long long int &counter) {
    counter++;
}

void outputResults1(UserData userData) {
    // Print statistics
    cout << "Number of pcap observer traffic: " << readable_bytes(userData.total_pcap_bytes) << endl;
    cout << "Number of bytes pcap actually captured: " << readable_bytes(userData.total_pcap_captured_bytes) << endl;

    cout << "Number of processed packets: " << userData.packet_counter << endl;

    cout << "Number of different IPv4 addresses: " << to_string(userData.found_ips.size()) << endl;

    cout << "Layer 3 Protocols (with packet count): " << endl;

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

    cout << "Total IPv4 payload: " << readable_bytes(userData.ipv4_payload) << endl;

    cout << "Layer 4 Protocols inside IPv4 (with packet count):" << endl;

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

    cout << "Total TCP payload bytes: " << readable_bytes(userData.tcp_payload) << endl;
    cout << "Total UDP payload bytes: " << readable_bytes(userData.udp_payload) << endl;

    cout << "IPv4 flows: " << userData.layer_3_flows.size() << endl;
    cout << "TCP/UPD flows: " << userData.layer_4_flows.size() << endl;


    std::multimap<string, int> m;
    std::multimap<int, string> m2;

    for (auto &elem : userData.tcp_syn_ack) {

            char str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(elem.destination), str, INET_ADDRSTRLEN);

        std::multimap<string, int>::iterator it = m.find(str);
        if (it != m.end()){
            it->second = (it->second+1);
        }
        else{
            m.insert(std::make_pair(str, 1));  
        }
    }

    for(multimap<string,int>::iterator it = m.begin(); it != m.end(); ++it) {
        m2.insert(std::make_pair(it->second, it->first));
    }
     cout << "Top 50 IP addresses that did not finish the three-way TCP handshake:" << endl;
    int ipcount = 0;
    for(multimap<int,string>::reverse_iterator it = m2.rbegin(); it != m2.rend(); ++it) {
        if(ipcount >= 50) break;
        cout << it->first << " - " << it->second << "\n";
        ipcount++;
    }


    cout << "Top 5 network scan suspects:" << endl;

    // delete entries that are not response to syn request
    std::multimap<string, int> found_icmp2;
     for (auto &elem : userData.tcp_syn) {
                char str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(elem.source), str, INET_ADDRSTRLEN);

                std::multimap<string, int>::iterator it2 = userData.found_icmp.find(str);
                if (it2 != userData.found_icmp.end()){
                    // is a response
                    // The two highest for example are no responses to unanswered syn messages
                    // 125 - 203.13.151.236
                    // 54 - 165.19.180.177
                    std::multimap<string, int>::iterator it3 = found_icmp2.find(str);
                    if (it3 == found_icmp2.end()){
                        // is not already in list
                        found_icmp2.insert(std::make_pair(it2->first, it2->second));
                    }
                }
    }


    std::multimap<int, string> found_icmp3;

    for(multimap<string, int>::iterator it = found_icmp2.begin(); it != found_icmp2.end(); ++it) {
        found_icmp3.insert(std::make_pair(it->second, it->first));
    }

    ipcount = 0;
    for(multimap<int,string>::reverse_iterator it = found_icmp3.rbegin(); it != found_icmp3.rend(); ++it) {
        if(ipcount >= 5) break;
        cout << it->first << " - " << it->second << "\n";
        ipcount++;
    }


    cout << "TCP connections without SYN/ACK response to SYN: " << userData.tcp_syn.size() << endl;
    cout << "TCP connections without ACK response to SYN/ACK: " << userData.tcp_syn_ack.size() << endl;

    IPv4Flow_t ipv4MaxFlow = {};
    uint64_t maxFlow = 0;
    for (auto &it : userData.layer_3_flows) {
        if (it.second > maxFlow) {
            ipv4MaxFlow = it.first;
            maxFlow = it.second;
        }
    }
    cout << "Max IPv4 flow from " << inet_ntoa(ipv4MaxFlow.source) << " to " << inet_ntoa(ipv4MaxFlow.destination) <<
         ": " << readable_bytes(maxFlow) << endl;

    Layer4Flow_t layer4MaxFlow = {};
    maxFlow = 0;
    for (auto &it : userData.layer_4_flows) {
        if (it.second > maxFlow) {
            layer4MaxFlow = it.first;
            maxFlow = it.second;
        }
    }
    cout << "Layer4 flow from " << inet_ntoa(layer4MaxFlow.source) << " port " << ntohs(layer4MaxFlow.source_port) <<
         " to " << inet_ntoa(layer4MaxFlow.destination) << " port " << ntohs(layer4MaxFlow.destination_port) <<
         ": " << readable_bytes(maxFlow) << endl;
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
            // payload should be the total packet size minus the header size (always: contained packet length > ip_header_size)
            unsigned int ip_packet_payload_length = 0;
            if (ip_header_size < contained_packet_length) {
                ip_packet_payload_length = contained_packet_length - ip_header_size;
            } else {
                // never happens
                cout << "IP header greater than the available data" << endl;
            }
            ud->ipv4_payload += ip_packet_payload_length;


            // insert the IPv4 flow
            IPv4Flow_t iPv4Flow = {};
            iPv4Flow.source = ip->ip_src;
            iPv4Flow.destination = ip->ip_dst;

            if (ud->layer_3_flows.count(iPv4Flow) > 0) {
                ud->layer_3_flows[iPv4Flow] += ip_packet_payload_length;
            } else {
                ud->layer_3_flows[iPv4Flow] = ip_packet_payload_length;
            }

            // count the layer 4 protocols inside IPv4
            if (ud->layer_4_protocol_counter.find(ip->ip_p) == ud->layer_4_protocol_counter.end()) {
                // protocol is not in the map, set to 1
                ud->layer_4_protocol_counter[ip->ip_p] = 1;
            } else {
                ud->layer_4_protocol_counter[ip->ip_p]++;
            }

            Layer4Flow_t layer4Flow = {};
            layer4Flow.source = ip->ip_src;
            layer4Flow.destination = ip->ip_dst;

            if (ip->ip_p == IPPROTO_TCP) {
                const struct tcphdr *tcp_header;
                // ip payload should start directly after ip header
                tcp_header = (struct tcphdr *) (packet + ETHERNET_HEADER_SIZE + ip_header_size);
                // th_off is the header size in blocks of 32 bits (= 4byte)
                int tcp_header_size = tcp_header->th_off * 4;


                // sometimes the tcp header is bigger than the possible left payload
                if (tcp_header_size < ip_packet_payload_length) {
                    ud->tcp_payload += ip_packet_payload_length - tcp_header_size;

                    // insert the flow
                    layer4Flow.source_port = tcp_header->th_sport;
                    layer4Flow.destination_port = tcp_header->th_dport;
                    layer4Flow.is_tcp = true;

                    if (ud->layer_4_flows.count(layer4Flow) > 0) {
                        ud->layer_4_flows[layer4Flow] += ip_packet_payload_length - tcp_header_size;
                    } else {
                        ud->layer_4_flows[layer4Flow] = ip_packet_payload_length - tcp_header_size;
                    }
                }

                TcpHandshake handshake{};
                handshake.source = ip->ip_src;
                handshake.destination = ip->ip_dst;
                handshake.source_port = tcp_header->th_sport;
                handshake.destination_port = tcp_header->th_dport;

                // check for the tcp handshake
                if (tcp_header->syn == 1 && tcp_header->ack == 0) {
                    // syn package from client to server to init a connection
                    // create a handshake object and add to the list of connection attempts
                    handshake.seq = ntohl(tcp_header->seq);
                    ud->tcp_syn.insert(handshake);
                } else if (tcp_header->syn == 1 && tcp_header->ack == 1) {
                    // syn-ack package: response from server to client to a syn package
                    // find the syn entry and update it
                    handshake.seq = ntohl(tcp_header->ack_seq) - 1;
                    handshake.swap();
                    if (ud->tcp_syn.count(handshake) > 0) {
//                        cout << "syn seq: " << (*ud->tcp_syn.find(handshake)).seq << ", syn ack seq:"
//                             << ntohl(tcp_header->ack_seq) << " new seq " << ntohl(tcp_header->seq) << endl;

                        ud->tcp_syn.erase(handshake);

                        // switch back
                        handshake.swap();
                        handshake.seq = ntohl(tcp_header->seq);
                        ud->tcp_syn_ack.insert(handshake);
                    }
                } else if (tcp_header->syn == 0 && tcp_header->ack == 1) {
                    // ack package from client to server as response to the syn-ack package
                    handshake.seq = ntohl(tcp_header->ack_seq) - 1;
                    // handshake complete, remove it from the list
                    if (ud->tcp_syn_ack.count(handshake) > 0) {
//                        cout << "syn seq: " << (*ud->tcp_syn_ack.find(handshake)).seq
//                             << ", syn ack seq:" << ntohl(tcp_header->ack_seq) << endl;
                        ud->tcp_syn_ack.erase(handshake);
                    }
                } else if (tcp_header->rst == 1) {
                    // connection failed, remove the attempt
                    handshake.seq = 0;
                    if (ud->tcp_syn.count(handshake) > 0) {
                        ud->tcp_syn.erase(handshake);
                    }
                    if (ud->tcp_syn_ack.count(handshake) > 0) {
                        ud->tcp_syn_ack.erase(handshake);
                    }
                    handshake.swap();
                    if (ud->tcp_syn.count(handshake) > 0) {
                        ud->tcp_syn.erase(handshake);
                    }
                    if (ud->tcp_syn_ack.count(handshake) > 0) {
                        ud->tcp_syn_ack.erase(handshake);
                    }
                }
            } else if (ip->ip_p == IPPROTO_UDP) {
                const struct udphdr *udp_header;
                // ip payload should start directly after ip header
                udp_header = (struct udphdr *) (packet + ETHERNET_HEADER_SIZE + ip_header_size);


                // udp payload is total length minus header length
                if (UDP_HEADER_SIZE < ip_packet_payload_length) {
                    ud->udp_payload += ip_packet_payload_length - UDP_HEADER_SIZE;


                    // insert the flow
                    layer4Flow.source_port = udp_header->uh_sport;
                    layer4Flow.destination_port = udp_header->uh_dport;
                    layer4Flow.is_tcp = false;

                    if (ud->layer_4_flows.count(layer4Flow) > 0) {
                        ud->layer_4_flows[layer4Flow] += ip_packet_payload_length - UDP_HEADER_SIZE;
                    } else {
                        ud->layer_4_flows[layer4Flow] = ip_packet_payload_length - UDP_HEADER_SIZE;
                    }

                } else {
                    // never happens
                    cout << "udp header greater than remaining payload" << endl;
                }
            }  else if (ip->ip_p == IPPROTO_ICMP) {
                const struct icmphdr *icmp_header;

                icmp_header = (struct icmphdr *) (packet + ETHERNET_HEADER_SIZE + ip_header_size);

                if (icmp_header->type == ICMP_DEST_UNREACH && icmp_header->code == ICMP_PORT_UNREACH){
                    char str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(ip->ip_dst.s_addr), str, INET_ADDRSTRLEN);


                    std::multimap<string, int>::iterator it = ud->found_icmp.find(str);
                    if (it != ud->found_icmp.end()){
                        it->second = (it->second+1);
                    }
                    else{
                        ud->found_icmp.insert(std::make_pair(str, 1)); 
                    }

                }

            }

        } else {
            // does never happen, remove in final version
            cout << "IP packet was not IPv4!!!" << endl;
        }
    }
}


void packetHandler2(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    auto *ud = (struct UserData *) userData;

    increaseCounter(ud->packet_counter);

    // len is length of the original packet
    ud->total_pcap_bytes += pkthdr->len;
    // caplen is the available length in this capture
    ud->total_pcap_captured_bytes += pkthdr->caplen;

    u_int contained_packet_length = pkthdr->len - 4;

    const struct ip *ip;
    // ip packet begins 4 crappy loopback bytes
    ip = (struct ip *) (packet + 4);

    // only handle IPv4
    if (ip->ip_v == 4) {
        // the header length fields denotes the length in blocks of 32 bit = 4 byte
        unsigned int ip_header_size = ip->ip_hl * 4;
        // payload should be the total packet size minus the header size (always: contained packet length > ip_header_size)
        unsigned int ip_packet_payload_length = 0;
        if (ip_header_size < contained_packet_length) {
            ip_packet_payload_length = contained_packet_length - ip_header_size;
        } else {
            // never happens
            cout << "IP header greater than the available data" << endl;
        }

        if (ip->ip_p == IPPROTO_TCP) {
            const struct tcphdr *tcp_header;
            // ip payload should start directly after ip header
            tcp_header = (struct tcphdr *) (packet + ip_header_size + 4);
            // th_off is the header size in blocks of 32 bits (= 4byte)
            int tcp_header_size = tcp_header->th_off * 4;

            // sometimes the tcp header is bigger than the possible left payload
            if (tcp_header_size < ip_packet_payload_length) {
                string payload((char *) (packet + ip_header_size + tcp_header_size + 4));

                //request starts with GET or POST, response starts with HTTP
                if (payload.find("GET") == 0 || payload.find("POST") == 0 || payload.find("HTTP") == 0) {

                    unsigned long i = payload.find("Authorization: ");
                    if (i != payload.npos) {
                        // HTTP headers are separated by windows-style line breaks
                        unsigned long nextBreak = payload.find("\r\n", i);
                        // auth header name is 15 chars long
                        string header = payload.substr(i + 15, nextBreak - i - 15);
                        cout << "found http auth: " << header << endl;
                    }
                }
            }
        }
    }
}

string readable_bytes(uint64_t bytes) {
    long double size = bytes;
    const char *units[] = {"B", "kB", "MB", "GB", "TB"};
    int i;
    for (i = 0; size > 1024; i++) {
        size /= 1024;
    }
    auto *out = new char[10];
    sprintf(out, "%Lf %s", size, units[i]);
    return out;
}
