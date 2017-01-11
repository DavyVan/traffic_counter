#include <pcap.h>
#include <cstdio>
#include <memory.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <signal.h>
#include <inttypes.h>
#include <cstdlib>
#include <arpa/inet.h>
#include <cstring>
using namespace std;

unsigned long long int bytes_count = 0;
unsigned long long int pkt_count = 0;

void display_help()
{
    puts("Usage: traffic_counter {optons}");
    puts("options: DEVICE IP");
}

void SIGINT_handler(int sig)
{
    // printf my be un-safe in signal function
    printf("total bytes: %llu\n", bytes_count);
    printf("Total packets: %llu\n", pkt_count);
    puts("Program terminating...");
    puts("Goodbye.");
    exit(1);
}

// Do something when we get a new packet
void got_packet(u_char *args, const pcap_pkthdr *header, const u_char *packet)
{
    // fpter is now point to the begin of IP protocal
    const u_char *fptr = packet + ETH_HLEN;
    const iphdr *ipheader = (iphdr*)fptr;

    //printf("tot_len: %hd\n", ntohs(ipheader->tot_len));
    bytes_count += ntohs(ipheader->tot_len);
    pkt_count += 1;
}

int main(int argc, char *argv[])
{
    if(argc < 3)
    {
        puts("Error: Missing Arguments");
        display_help();
        return -1;
    }

    // Register signal hendler
    signal(SIGINT, SIGINT_handler);

    // Some variables that pcap will use
    pcap_t *handle;
    char *device = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr pkthdr;
    const u_char *packet;
    bpf_program fp;
    char filter_exp[50] = "host ";
    strcat(filter_exp, argv[2]);
    bpf_u_int32 mask;
    bpf_u_int32 net;

    // Open a pcap transaction
    handle = pcap_open_live(device, BUFSIZ, 0, 0, errbuf);
    if (handle == NULL)
    {
        printf("Couldn't open device %s: %s\n", device, errbuf);
        return -1;
    }

    // pcap filter
    // obtain network properties of chosen device
    if(pcap_lookupnet(device, &net, &mask, errbuf) == -1)
    {
        printf("Can't get netmask for device %s\n", device);
        net = 0;
        mask = 0;
    }
    char t[INET_ADDRSTRLEN + 1];
    inet_ntop(AF_INET, &net, t, INET_ADDRSTRLEN);
    printf("%s\n", t);
    // compile filter expression
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    // Apple filter
    if(pcap_setfilter(handle, &fp) == -1)
    {
        printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }

    pcap_loop(handle, -1, got_packet, NULL);
}
