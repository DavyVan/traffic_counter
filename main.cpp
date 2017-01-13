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
#include <unistd.h>
using namespace std;

#define ARGC 2

unsigned long long int bytes_count = 0;
unsigned long long int pkt_count = 0;

void display_help()
{
    puts("Usage: traffic_counter {optons}");
    puts("options: ");
    puts("         -i name of interface");
    puts("         -h IP address to sniff");
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
    // Handle the Arguments
    char *device;
    char *sniff_ip;
    int c;
    int _argc = 0;
    while ((c = getopt(argc, argv, "i:h:")) != -1)
    {
        switch (c)
        {
            case 'i':
                device = optarg;
                _argc++;
                break;
            case 'h':
                sniff_ip = optarg;
                _argc++;
                break;
            case '?':
            default:
                puts("Error: Missing/Wrong Arguments. Exit.");
                display_help();
                return -1;
        }
    }
    if(_argc != ARGC)
    {
        puts("Error: Missing Arguments");
        display_help();
        return -1;
    }

    printf("Device: %s\n", device);
    printf("IP Address: %s\n", sniff_ip);

    // Register signal hendler
    signal(SIGINT, SIGINT_handler);

    // Some variables that pcap will use
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_pkthdr pkthdr;
    const u_char *packet;
    bpf_program fp;
    char filter_exp[100] = "not port 8030 and not port 8031 and not port 9000 and host ";
    strcat(filter_exp, sniff_ip);
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

    printf("Sniffing...\n");
    pcap_loop(handle, -1, got_packet, NULL);
}
