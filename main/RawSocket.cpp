#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <iostream>
#include <stdexcept>

char __buf[2048];

int main(int argc, char *argv[]) try{
   int sock;

   // if(argc != 2)throw std::invalid_argument("invalid argument");

   sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
   if(sock<0) throw std::logic_error("could not create a socket");

   char *buf = __buf;
   while(true){
      static size_t n = 0;
      struct sockaddr_in from;
      socklen_t fromlen = sizeof(from);

      n = recvfrom(sock,buf,sizeof(buf),0,(struct sockaddr *)&from,&fromlen);
      if(n<1) throw std::logic_error("could not recv");

      std::cout<< n <<" : "<< buf<< std::endl;
   }

   close(sock);

   return 0;
} catch(const std::logic_error &e){
   std::cerr<< e.what()<< std::endl;
   exit(0);
} catch(const std::invalid_argument &e){
   std::cerr<< e.what()<< std::endl;
   exit(0);
}
