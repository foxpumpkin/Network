// cpp libraries
#include <sys/select.h>
#include <pcap/pcap.h>

// c libraries
#include <iostream>

using namespace std;

int main( int argc, char *argv[]){
  auto in_pcap= pcap_open_live( argv[ 1], 1600, 1, -1, 0); 
  auto out_pcap= pcap_open_live( argv[ 2], 1600, 1, -1, 0); 

  auto in_fd= pcap_get_selectable_fd( in_pcap);
  bpf_program fp;
  // int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
  pcap_compile( in_pcap, &fp, "", 1, 0);
  // int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
  pcap_setfilter( in_pcap, &fp);

  auto out_fd= pcap_get_selectable_fd( out_pcap);
  // int pcap_compile(pcap_t *p, struct bpf_program *fp, const char *str, int optimize, bpf_u_int32 netmask);
  pcap_compile( out_pcap, &fp, "", 1, 0);
  // int pcap_setfilter(pcap_t *p, struct bpf_program *fp);
  pcap_setfilter( out_pcap, &fp);

  fd_set readfds;
  while( true) try{
    FD_ZERO( &readfds);
    FD_SET( in_fd, &readfds);
    FD_SET( out_fd, &readfds);
    auto ret= select( out_fd+ 1, &readfds, 0, 0, 0);
    if( ret< 0) throw invalid_argument( " error in select ");

    if( FD_ISSET( in_fd, &readfds)){
      struct pcap_pkthdr phdr;
      auto frame= pcap_next( in_pcap, &phdr);
      pcap_inject( out_pcap, frame, phdr.caplen);
    }
    if( FD_ISSET( out_fd, &readfds)){
      struct pcap_pkthdr phdr;
      auto frame= pcap_next( out_pcap, &phdr);
      pcap_inject( in_pcap, frame, phdr.caplen);
    }
  } catch( invalid_argument &e){
    cerr<< e.what()<< endl;
  }
}
