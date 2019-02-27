#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    int sockfd;
    struct sockaddr_storage server_address;
    struct sockaddr_storage from_address;
    unsigned int echo_port;
    unsigned int from_size;
    char server_IP[]="::1";
    char string[]="HelloWorld!!";
    char buf[1500];
    int rc;

    echo_port = 22222;        // 送信ポート

    if((strlen(string))>1500){
      printf("error1");
      exit(1);
    }

    if((sockfd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP))<0){
        printf("error2");
        exit(1);
    }


     int on=1;
     setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, (char *)&on, sizeof(on));


     struct sockaddr_in6 sin;
     memset (&sin, 0, sizeof (sin));
     sin.sin6_family = AF_INET6;
     int ret = inet_pton(AF_INET6, server_IP, sin.sin6_addr.s6_addr);
     sin.sin6_port = htons(echo_port);
     memcpy (&server_address, &sin, sizeof (sin));

    if(sendto(sockfd, string, strlen(string), 0,
        (struct sockaddr *)&server_address, sizeof(sockaddr_in6))
        != strlen(string)){
        printf("error3");
        exit(1);
    }

    from_size = sizeof(sockaddr_in6);

    if((rc = recvfrom(sockfd, buf, 1500, 0,
        (struct sockaddr *)&from_address, (socklen_t *)sizeof(sockaddr_in6)))
        == 0){
        printf("error4");
        exit(1);
    }
        
//    buf[rc] = 0;
    printf("Received: %s\n", buf);
    close(sockfd);
    exit(0);

}

 
