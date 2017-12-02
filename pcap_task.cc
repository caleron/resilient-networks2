#include <iostream>
#include <map>
#include <vector>
#include <pcap.h>
#include <pcap/bpf.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace std;

struct UserData {
  // Link type
  int data_link;
  // Basic counting of packets
  unsigned long long int packet_counter = 0;
  // Whatever you need, define it here
  // ...
};

void increaseCounter(unsigned long long int& counter);

// Prototype that processes every packet
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);


// Main of the programm
int main(int argc, char *argv[]) {

  // Read argument command line
  if (argc != 2 && argc != 3) {
    cout << "Use the file name as first command line argument plus optionally the number of packets to process" << endl;
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
  if (pcap_loop(descr, nPackets, packetHandler, (unsigned char*)&userData) < 0) {
    cout << "pcap_loop() failed: " << pcap_geterr(descr);
    return 1;
  }

  // Print statistics
  cout << "Number of processed packets: " << userData.packet_counter << endl;

  // Everything comes to an end...
  return 0;
}

void increaseCounter(unsigned long long int& counter) {
  counter++;
}

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
  // Setup variables
  const struct ether_header* ethernetHeader;

  struct UserData *ud = (struct UserData*)userData;

  // TODO: Increase packet counter

  // Get Link Header (layer 2)
  ethernetHeader = (struct ether_header*)packet;

  // TODO: ...

}

