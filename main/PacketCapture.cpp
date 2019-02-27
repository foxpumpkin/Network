#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>

#include <stdexcept>
#include <iostream>
#include <map>
#include <string>

using namespace std;

static map<uint16_t,string> network_protocol_string;
static map<uint16_t,string> transport_protocol_string;
void initialize();
void handler( u_char *userdata, const struct pcap_pkthdr *h, const u_char *p);
void print( u_char *userdata, const struct pcap_pkthdr *h, const u_char *p);
void print_ethaddr( const u_char *p, uint16_t *protocol, size_t *itr);
void print_ip( const u_char *p, uint16_t *protocol, size_t *itr);
void print_align_right( const char string[], const size_t width);
void print_align_center( const char string[], const size_t width);
int main( int argc, char *argv[] ) try{
   initialize();

   char *device;
   pcap_t *pd;
   int snaplen = 64;
   int pflag = 0;
   int timeout = 1000;
   char ebuf[PCAP_ERRBUF_SIZE];
   bpf_u_int32 localnet, netmask;
   pcap_handler callback;
   //struct bpf_program fcode;

   if (argc == 1) throw invalid_argument("You muse specify network interface.");

   device = argv[1];
   pd = pcap_open_live(device, snaplen, !pflag, timeout, ebuf);
   if (!pd) throw invalid_argument("could not open pcap deivce");

   if (pcap_lookupnet(device, &localnet, &netmask, ebuf)< 0) throw invalid_argument("Can't get interface informartions");

   /* setting and compiling packet filter */
#if 0
   /* In this example, capture HTTP and FTP packets only */
   if (pcap_compile(pd, &fcode, "port 80 or 20 or 21", 1, netmask) < 0) {
      fprintf(stderr, "can't compile fileter\n");
      exit(1);
   }
   if (pcap_setfilter(pd, &fcode) < 0) {
      fprintf(stderr, "can't set filter\n");
      exit(1);
   }
#endif

   /* set call back function for output */
   /* in this case output is print-out procedure for ethernet addresses */
   callback = handler;

   /* loop packet capture util picking 1024 packets up from interface. */
   /* after 1024 packets dumped, pcap_loop function will finish. */
   /* argument #4 NULL means we have no data to pass call back function. */

   if (pcap_loop(pd, 0, callback, NULL) < 0) throw logic_error("pcap_loop: error occurred");

   /* close capture device */
   pcap_close(pd);

   exit(0);
} catch( const invalid_argument &e){
   cerr<< "(invalid argument) "<< e.what()<< endl;
   return 0;
} catch( const logic_error &e){
   cerr<< "(logic error) "<< e.what()<< endl;
   return 0;
}

void handler( u_char *userdata, const struct pcap_pkthdr *h, const u_char *p) {
   print(userdata, h, p);
}

void print( u_char *userdata, const struct pcap_pkthdr *h, const u_char *p)try{
   printf("- - - - - - - - [%4d] - - - - - - - -\n", h->len);
   uint16_t internet_layer = 0;
   uint16_t transport_layer = 0;
   size_t itr = 0;
   print_ethaddr( p, &internet_layer, &itr);
   switch(internet_layer){
      case ETHERTYPE_PUP: throw invalid_argument("unknown protocol");
      case ETHERTYPE_IP:
                          print_ip(p,&transport_layer,&itr);
                          break;
      case ETHERTYPE_ARP: throw invalid_argument("unknown protocol");
      case ETHERTYPE_REVARP: throw invalid_argument("unknown protocol");
      case ETHERTYPE_VLAN: throw invalid_argument("unknown protocol");
      case ETHERTYPE_IPV6: throw invalid_argument("unknown protocol");
      case ETHERTYPE_PAE: throw invalid_argument("unknown protocol");
      case ETHERTYPE_RSN_PREAUTH: throw invalid_argument("unknown protocol");
      case ETHERTYPE_LOOPBACK: throw invalid_argument("unknown protocol");
      default: throw invalid_argument("unknown protocol");
   }
} catch(const invalid_argument &e){
   cerr<< "(print) "<< e.what()<< endl;
   return;
}

/* print time stamp and ethernet addresses from passed data by pcap_loop */
void print_ethaddr( const u_char *p, uint16_t *protocol, size_t *itr) {
   struct ether_header *eh;

   eh = (struct ether_header *)p;

   for ( int i= 1; i<= ETHER_ADDR_LEN; ++i) {
      printf("%02x", (int)eh->ether_shost[i]);
      printf("%c",( i!= ETHER_ADDR_LEN)?':':' ');
   } printf("-> ");

   for ( int i= 1; i<= ETHER_ADDR_LEN; ++i) {
      printf("%02x", (int)eh->ether_dhost[i]);
      printf("%c",( i!= ETHER_ADDR_LEN)?':':' ');
   } printf("\n");

   printf("           0x%04x",ntohs((short)eh->ether_type));
   printf(" -> ");
   map<uint16_t,string>::iterator protocol_itr = network_protocol_string.find(ntohs(eh->ether_type));
   printf("%s\n",(*protocol_itr).second.c_str());

   *protocol = ntohs((short)eh->ether_type);
   *itr = sizeof(struct ether_header);
}
void print_ip( const u_char *p, uint16_t *protocol, size_t *itr){
   struct ip *iphdr = (struct ip *)(p + *itr);
   static char message[128];
   memset(message,0,sizeof(message));
   sprintf(message,"v%u(%uoct) ttl(%u)  %s%s%s\n",iphdr->ip_v,iphdr->ip_hl*4,iphdr->ip_ttl,
         iphdr->ip_off&IP_RF?"RF ":"",iphdr->ip_off&IP_RF?"DF ":"",iphdr->ip_off&IP_MF?"MF":"");
   //printf("  type of service -> %u\n",iphdr->ip_tos);
   //printf("     total length -> %u\n",ntohs(iphdr->ip_len));
   //printf("   identification -> 0x%04x\n",ntohs(iphdr->ip_id));
   //printf("  fragment offset -> %s%s%s\n",
   //      iphdr->ip_off&IP_RF?"RF ":"",iphdr->ip_off&IP_RF?"DF ":"",iphdr->ip_off&IP_MF?"MF":"");
   //printf("     time to live -> %u\n",iphdr->ip_ttl);
   //printf("         checksum -> 0x%04x\n",ntohs(iphdr->ip_sum));
   print_align_center(message,38);

   static char addr[16]; // xxx.xxx.xxx.xxx + null
   memset(addr,0,sizeof(addr));
   static struct hostent *src_host, *dst_host;
   static struct in_addr src_addr4rev, dst_addr4rev;
   sprintf(addr,"%u.%u.%u.%u",
         (iphdr->ip_src.s_addr&0x000000FF)>>0,
         (iphdr->ip_src.s_addr&0x0000FF00)>>8,
         (iphdr->ip_src.s_addr&0x00FF0000)>>16,
         (iphdr->ip_src.s_addr&0xFF000000)>>24);
   src_addr4rev.s_addr = inet_addr(addr);
   src_host = gethostbyaddr((const char *)&src_addr4rev.s_addr,sizeof(src_addr4rev.s_addr), AF_INET);
   print_align_right(addr,17);
   printf("(%s)\n",src_host?src_host->h_name:"no domain");
   
   puts("");
   sprintf(addr,"%u.%u.%u.%u",
         (iphdr->ip_dst.s_addr&0x000000FF)>>0,
         (iphdr->ip_dst.s_addr&0x0000FF00)>>8,
         (iphdr->ip_dst.s_addr&0x00FF0000)>>16,
         (iphdr->ip_dst.s_addr&0xFF000000)>>24);
   dst_addr4rev.s_addr = inet_addr(addr);
   dst_host = gethostbyaddr((const char *)&dst_addr4rev.s_addr,sizeof(dst_addr4rev.s_addr), AF_INET);
   print_align_right(addr,17);
   printf("(%s)\n",dst_host?dst_host->h_name:"no domain");


   map<uint16_t,string>::iterator protocol_itr = transport_protocol_string.find(iphdr->ip_p);
   printf("             0x%02x -> %s\n",iphdr->ip_p,(*protocol_itr).second.c_str());

   *protocol = iphdr->ip_p;
   *itr += (iphdr->ip_hl * 4);
}
void initialize(){
   network_protocol_string.insert(make_pair(0x0200,"PUP"));
   network_protocol_string.insert(make_pair(0x0800,"IP"));
   network_protocol_string.insert(make_pair(0x0806,"ARP"));
   network_protocol_string.insert(make_pair(0x8035,"REVARP"));
   network_protocol_string.insert(make_pair(0x8100,"VLAN"));
   network_protocol_string.insert(make_pair(0x86dd,"IPV6"));
   network_protocol_string.insert(make_pair(0x888e,"PAE"));
   network_protocol_string.insert(make_pair(0x88c7,"RSN PREAUTH"));
   network_protocol_string.insert(make_pair(0x9000,"LOOPBACK"));

   transport_protocol_string.insert(make_pair(IPPROTO_IP,"IP"));
   transport_protocol_string.insert(make_pair(IPPROTO_HOPOPTS,"HOPOPTS"));
   transport_protocol_string.insert(make_pair(IPPROTO_ICMP,"ICMP"));
   transport_protocol_string.insert(make_pair(IPPROTO_IGMP,"IGMP"));
   transport_protocol_string.insert(make_pair(IPPROTO_GGP,"GGP"));
   transport_protocol_string.insert(make_pair(IPPROTO_IPV4,"IPv4"));
   transport_protocol_string.insert(make_pair(IPPROTO_TCP,"TCP"));
   transport_protocol_string.insert(make_pair(IPPROTO_ST,"ST"));
   transport_protocol_string.insert(make_pair(IPPROTO_EGP,"EGP"));
   transport_protocol_string.insert(make_pair(IPPROTO_PIGP,"PIGP"));
   transport_protocol_string.insert(make_pair(IPPROTO_RCCMON,"RCCMON"));
   transport_protocol_string.insert(make_pair(IPPROTO_NVPII,"NVPII"));
   transport_protocol_string.insert(make_pair(IPPROTO_PUP,"PUP"));
   transport_protocol_string.insert(make_pair(IPPROTO_ARGUS,"ARGUS"));
   transport_protocol_string.insert(make_pair(IPPROTO_EMCON,"EMCON"));
   transport_protocol_string.insert(make_pair(IPPROTO_XNET,"XNET"));
   transport_protocol_string.insert(make_pair(IPPROTO_CHAOS,"CHAOS"));
   transport_protocol_string.insert(make_pair(IPPROTO_UDP,"UDP"));
   transport_protocol_string.insert(make_pair(IPPROTO_MUX,"MUX"));
   transport_protocol_string.insert(make_pair(IPPROTO_MEAS,"MEAS"));
   transport_protocol_string.insert(make_pair(IPPROTO_HMP,"HMP"));
   transport_protocol_string.insert(make_pair(IPPROTO_PRM,"PRM"));
   transport_protocol_string.insert(make_pair(IPPROTO_IDP,"IDP"));
   transport_protocol_string.insert(make_pair(IPPROTO_TRUNK1,"TRUNK1"));
   transport_protocol_string.insert(make_pair(IPPROTO_TRUNK2,"TRUNK2"));
   transport_protocol_string.insert(make_pair(IPPROTO_LEAF1,"LEAF1"));
   transport_protocol_string.insert(make_pair(IPPROTO_LEAF2,"LEAF2"));
   transport_protocol_string.insert(make_pair(IPPROTO_RDP,"RDP"));
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IRTP            28              /* Reliable Transaction */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_TP              29              /* tp-4 w/ class negotiation */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_BLT             30              /* Bulk Data Transfer */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_NSP             31              /* Network Services */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_INP             32              /* Merit Internodal */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SEP             33              /* Sequential Exchange */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_3PC             34              /* Third Party Connect */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IDPR            35              /* InterDomain Policy Routing */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_XTP             36              /* XTP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_DDP             37              /* Datagram Delivery */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_CMTP            38              /* Control Message Transport */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_TPXX            39              /* TP++ Transport */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IL              40              /* IL transport protocol */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define         IPPROTO_IPV6            41              /* IP6 header */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SDRP            42              /* Source Demand Routing */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define         IPPROTO_ROUTING 43              /* IP6 routing header */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define         IPPROTO_FRAGMENT        44              /* IP6 fragmentation header */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IDRP            45              /* InterDomain Routing*/
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define         IPPROTO_RSVP            46              /* resource reservation */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_GRE             47              /* General Routing Encap. */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_MHRP            48              /* Mobile Host Routing */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_BHA             49              /* BHA */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_ESP             50              /* IP6 Encap Sec. Payload */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_AH              51              /* IP6 Auth Header */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_INLSP           52              /* Integ. Net Layer Security */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SWIPE           53              /* IP with encryption */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_NHRP            54              /* Next Hop Resolution */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define         IPPROTO_ICMPV6  58              /* ICMP6 */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define         IPPROTO_NONE            59              /* IP6 no next header */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define         IPPROTO_DSTOPTS 60              /* IP6 destination option */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_AHIP            61              /* any host internal protocol */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_CFTP            62              /* CFTP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_HELLO           63              /* "hello" routing protocol */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SATEXPAK        64              /* SATNET/Backroom EXPAK */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_KRYPTOLAN       65              /* Kryptolan */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_RVD             66              /* Remote Virtual Disk */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IPPC            67              /* Pluribus Packet Core */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_ADFS            68              /* Any distributed FS */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SATMON          69              /* Satnet Monitoring */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_VISA            70              /* VISA Protocol */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IPCV            71              /* Packet Core Utility */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_CPNX            72              /* Comp. Prot. Net. Executive */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_CPHB            73              /* Comp. Prot. HeartBeat */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_WSN             74              /* Wang Span Network */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_PVP             75              /* Packet Video Protocol */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_BRSATMON        76              /* BackRoom SATNET Monitoring */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_ND              77              /* Sun net disk proto (temp.) */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_WBMON           78              /* WIDEBAND Monitoring */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_WBEXPAK         79              /* WIDEBAND EXPAK */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_EON             80              /* ISO cnlp */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_VMTP            81              /* VMTP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SVMTP           82              /* Secure VMTP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_VINES           83              /* Banyon VINES */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_TTP             84              /* TTP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IGP             85              /* NSFNET-IGP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_DGP             86              /* dissimilar gateway prot. */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_TCF             87              /* TCF */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IGRP            88              /* Cisco/GXS IGRP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_OSPFIGP         89              /* OSPFIGP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SRPC            90              /* Strite RPC protocol */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_LARP            91              /* Locus Address Resoloution */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_MTP             92              /* Multicast Transport */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_AX25            93              /* AX.25 Frames */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IPEIP           94              /* IP encapsulated in IP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_MICP            95              /* Mobile Int.ing control */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SCCSP           96              /* Semaphore Comm. security */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_ETHERIP         97              /* Ethernet IP encapsulation */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_ENCAP           98              /* encapsulation header */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_APES            99              /* any private encr. scheme */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_GMTP            100             /* GMTP*/
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_PIM             103             /* Protocol Independent Mcast */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_IPCOMP          108             /* payload compression (IPComp) */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_PGM             113             /* PGM */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_SCTP            132             /* SCTP */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_DIVERT          254             /* divert pseudo-protocol */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_RAW             255             /* raw IP packet */
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_MAX             256
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
#define IPPROTO_DONE            257
   transport_protocol_string.insert(make_pair(0,"IPPROTP_"));
}
void print_align_right( const char string[], const size_t width){
   size_t length = strnlen(string,width);
   for(size_t space= 0; space< (width-length); space++) printf(" ");
   printf("%s",string);
}

void print_align_center( const char string[], const size_t width){
   size_t length = strnlen(string,width);
   for(size_t space= 0; space< (width-length)/2; space++) printf(" ");
   printf("%s",string);
}
