#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h> 
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_storage server_address;
    struct sockaddr_storage client_address;
    socklen_t cli_addr_len;
    char buf[1500];
    unsigned int echo_port;
    int rc;

    echo_port = 22222;

    if((sockfd = socket(AF_INET6, SOCK_DGRAM, 0))<0){
       printf("error");
       exit(1);
    }

//option IPv6Only
     int on=1;
     setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on));

     memset(&server_address, 0, sizeof(server_address));
     struct sockaddr_in6 sin;
     memset (&sin, 0, sizeof (sin));
     sin.sin6_family = AF_INET6;
     sin.sin6_addr = in6addr_any;
     sin.sin6_port = htons(echo_port);
     memcpy (&server_address, &sin, sizeof (sin));


    if(bind(sockfd, (struct sockaddr *)&server_address, sizeof(sockaddr_in6))<0){
        printf("error");
        exit(1);
    }

    while(1){  // 無限ループ
        cli_addr_len = sizeof(sockaddr_in6);
        if((rc = recvfrom(sockfd, buf, 1500, 0,
            (struct sockaddr *)&client_address, &cli_addr_len))<0){
            printf("error");
            exit(1);
        }

        printf("Client address: %s\n",((struct sockaddr_in6 *)&client_address)->sin6_addr.s6_addr);

        if(sendto(sockfd, buf, sizeof(buf), 0,
            (struct sockaddr *)&client_address, sizeof(sockaddr_in6))< 1500){
            printf("error");
            exit(1);
            }
    }
}


