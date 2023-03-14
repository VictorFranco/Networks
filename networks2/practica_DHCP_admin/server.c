#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <net/if.h>

#define CLIENT_PORT 0x44
#define SERVER_PORT 0x43
#define PACK_SIZE   512
#define IPS_MANAGED 50

/************************/
// Author: Victor Franco
// Date:   06/07/2022
/************************/

struct sockaddr_in SERVER, CLIENT;
unsigned char paqEnv[PACK_SIZE], paqRec[PACK_SIZE];
int udp_socket, lbind, tam;
socklen_t lrecv;

unsigned char id_transaccion[4],cookie_magica[4],su_dir_ip[4],mac[6];
char ip_stored[IPS_MANAGED];
struct info {
    char type[1];
    char submask[4];
    char ip[4];
    char router[4];
    char dns[4];
};

struct info info_client;

unsigned char ip_server[4] = {192,168,2,64};
char domain_name[] = "vfranco.com";

char dictionary[][2][6] = {
{"a",{0xd0,0x77,0x14,0xbf,0xe9,0xd7}},
{"b",{0x00,0xe0,0x4c,0xa2,0x5c,0x22}},
{"c",{0xe4,0x5f,0x01,0x09,0x1d,0xa9}},
};

// type     submask                  ip              router/puerta              dns
struct info config_by_type[] = {
{"a",{0xFF,0xFF,0xFF,0x00},{0xc0,0xa8,0x02,0x01},{         0         },{         0         }},
{"b",{0xFF,0xFF,0xFF,0x00},{0xc0,0xa8,0x02,0x02},{0xc0,0xa8,0x02,0x40},{         0         }},
{"c",{0xFF,0xFF,0xFF,0x00},{0xc0,0xa8,0x02,0x03},{0xc0,0xa8,0x02,0x40},{0xc0,0xa8,0x02,0x40}},
};

void showBytes(unsigned char*block,int len) {
    for (int i=0; i<len; i++) {
        if(i%16 == 0) printf("\n");
        if(i%8 == 0)  printf("    ");
        printf("0x%02x ", block[i]);
    }
}

int DHCP_Discover() {
    struct timeval start, end;
    long mtime = 0, seconds,useconds;
    lrecv = sizeof(CLIENT);
    while(1) {
        tam = recvfrom(udp_socket,paqRec, PACK_SIZE, MSG_DONTWAIT, NULL, &lrecv);
        unsigned char message_type[] = {0x35,0x01,0x1};
        if(tam != -1 && !memcmp(message_type,paqRec+240,3)) break;
    }
    memcpy(id_transaccion,paqRec+4,4);
    memcpy(cookie_magica,paqRec+236,4);
    memcpy(mac,paqRec+28,6);
    printf("-------------------------\nid: 0x");
    for(int i=0; i<4; i++) printf("%02x",id_transaccion[i]);
    printf("\n-------------------------\n");
    printf("MAC: ");
    for(int i=0; i<6; i++) printf("%02x%s",mac[i],i==5?"":":");
    printf("\n");
    return tam != -1 ? 0 : -1;
}

int DHCP_Offer(char type[1]) {
    lrecv = sizeof(CLIENT);
    char tipo_mensaje = 0x02; //response
    paqEnv[0] = tipo_mensaje;
    char tipo_hardware = 0x01;//ethernet
    paqEnv[1] = tipo_hardware;
    char long_dir_hw = 0x06;
    paqEnv[2] = long_dir_hw;
    char saltos = 0x00;
    paqEnv[3] = saltos;
    memcpy(paqEnv+4,id_transaccion,4);
    char segundos[] = {0x00,0x00};
    memcpy(paqEnv+8,segundos,2);
    char indicadores[] = {0x00,0x00};
    memcpy(paqEnv+10,indicadores,2);
    char dir_ip_cliente[] = {0x00,0x00,0x00,0x00};
    memcpy(paqEnv+12,dir_ip_cliente,4);

    for(int i=0;i<5;i++)
        memset(info_client.type,0,2);

    for(int i=0; i<sizeof(config_by_type)/17;i++)
        if(!memcmp(config_by_type[i].type,type,1)) {
            info_client = config_by_type[i];
            break;
        }

    if(info_client.type[0]=='\0') return -1;

    memcpy(su_dir_ip,info_client.ip,4);
    memcpy(paqEnv+16,su_dir_ip,4);

    printf("IP:  ");
    for(int i=0; i<4; i++) printf("%d%s",su_dir_ip[i],i==3?"":".");
    printf("\n");

    char dir_ip_servidor[] = {0x00,0x00,0x00,0x00};
    memcpy(paqEnv+20,dir_ip_servidor,4);
    char dir_ip_gateway[] = {0x00,0x00,0x00,0x00};
    memcpy(paqEnv+24,dir_ip_gateway,4);
    char dir_hw_cliente[16];
    memset(dir_hw_cliente,0,16);
    memcpy(dir_hw_cliente,mac,6);
    memcpy(paqEnv+28,dir_hw_cliente,16);
    memset(paqEnv+44,0x00,64);    // nombre host servidor
    memset(paqEnv+108,0x00,128);  // nombre archivo inicio
    memcpy(paqEnv+236,cookie_magica,4);
    char opciones[80] = {0x35,0x01,0x02,
        // DHCP Server Identifier 192  168  2    64
                       0x36,0x04,0xc0,0xa8,0x02,0x40,
                       0x3a,0x04,0x00,0x05,0x46,0x00,
                       0x3b,0x04,0x00,0x09,0x3a,0x80,
                       0x33,0x04,0x00,0x0a,0x8c,0x00};
    memcpy(opciones+5,ip_server,4);                      // ip server
    int index = 27;
    char op_submask[] = {0x01,0x04};
    if(strlen(info_client.submask)) {
        memcpy(opciones+index,op_submask,2);
        memcpy(opciones+index+2,info_client.submask,4);  // subnet mask
        index += 6;
    }
    char op_router[] = {0x03,0x04};
    if(strlen(info_client.router)) {
        memcpy(opciones+index,op_router,2);
        memcpy(opciones+index+2,info_client.router,4);   // router
        index += 6;
    }
    char op_dns[]    = {0x06,0x04};
    if(strlen(info_client.dns)) {
        memcpy(opciones+index,op_dns,2);
        memcpy(opciones+index+2,info_client.dns,4);      // dns
        index += 6;
    }

    opciones[index++] = 0x0f;
    opciones[index++] = strlen(domain_name);             // domain name
    memcpy(opciones+index,domain_name,strlen(domain_name));
    index += strlen(domain_name);
    opciones[index++] = 0x00;
    opciones[index++] = 0xff;
    memcpy(paqEnv+240,opciones,index);

    tam = sendto(udp_socket, paqEnv, 240+index, 0, (struct sockaddr*)&CLIENT, lrecv);
    return tam != -1 ? 0 : -1;
}

int DHCP_Request() {
    struct timeval start, end;
    long mtime = 0, seconds,useconds;
    lrecv = sizeof(CLIENT);
    gettimeofday(&start, NULL);
    do {
        tam = recvfrom(udp_socket,paqRec, PACK_SIZE, MSG_DONTWAIT, NULL, &lrecv);
        unsigned char message_type[] = {0x35,0x01,0x3};
        if(tam != -1 && !memcmp(id_transaccion,paqRec+4,4) && !memcmp(message_type,paqRec+240,3))
            break;
        gettimeofday(&end, NULL);              //-------------------|
        seconds  = end.tv_sec  - start.tv_sec; //                   |--> time
        useconds = end.tv_usec - start.tv_usec;//                   |
        mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;//-------|
    } while(mtime < 2000);
    memcpy(id_transaccion,paqRec+4,4);
    memcpy(cookie_magica,paqRec+236,4);
    return tam != -1 ? 0 : -1;
}

int DHCP_Ack() {
    lrecv = sizeof(CLIENT);
    char tipo_mensaje = 0x02; //response
    paqEnv[0] = tipo_mensaje;
    char tipo_hardware = 0x01;//ethernet
    paqEnv[1] = tipo_hardware;
    char long_dir_hw = 0x06;
    paqEnv[2] = long_dir_hw;
    char saltos = 0x00;
    paqEnv[3] = saltos;
    memcpy(paqEnv+4,id_transaccion,4);
    char segundos[] = {0x00,0x00};
    memcpy(paqEnv+8,segundos,2);
    char indicadores[] = {0x00,0x00};
    memcpy(paqEnv+10,indicadores,2);
    char dir_ip_cliente[] = {0x00,0x00,0x00,0x00};
    memcpy(paqEnv+12,dir_ip_cliente,4);
    memcpy(paqEnv+16,su_dir_ip,4);
    char dir_ip_servidor[] = {0x00,0x00,0x00,0x00};
    memcpy(paqEnv+20,dir_ip_servidor,4);
    char dir_ip_gateway[] = {0x00,0x00,0x00,0x00};
    memcpy(paqEnv+24,dir_ip_gateway,4);
    char dir_hw_cliente[16];
    memset(dir_hw_cliente,0,16);
    memcpy(dir_hw_cliente,mac,6);
    memcpy(paqEnv+28,dir_hw_cliente,16);
    memset(paqEnv+44,0x00,64);    // nombre host servidor
    memset(paqEnv+108,0x00,128);  // nombre archivo inicio
    memcpy(paqEnv+236,cookie_magica,4);
    char opciones[80] = {0x35,0x01,0x05,
        // DHCP Server Identifier 192  168  2    64
                       0x36,0x04,0xc0,0xa8,0x02,0x40,
                       0x3a,0x04,0x00,0x05,0x46,0x00,
                       0x3b,0x04,0x00,0x09,0x3a,0x80,
                       0x33,0x04,0x00,0x0a,0x8c,0x00,
                       0x51,0x03,0x03,0xff,0xff};
    memcpy(opciones+5,ip_server,4);             // ip server
    int index = 35;
    char op_submask[] = {0x01,0x04};
    if(strlen(info_client.submask)) {
        memcpy(opciones+index,op_submask,2);
        memcpy(opciones+index+2,info_client.submask,4);  // subnet mask
        index += 6;
    }
    char op_router[] = {0x03,0x04};
    if(strlen(info_client.router)) {
        memcpy(opciones+index,op_router,2);
        memcpy(opciones+index+2,info_client.router,4);   // router
        index += 6;
    }
    char op_dns[]    = {0x06,0x04};
    if(strlen(info_client.dns)) {
        memcpy(opciones+index,op_dns,2);
        memcpy(opciones+index+2,info_client.dns,4);      // dns
        index += 6;
    }

    opciones[index++] = 0x0f;
    opciones[index++] = strlen(domain_name);             // domain name
    memcpy(opciones+index,domain_name,strlen(domain_name));
    index += strlen(domain_name);
    opciones[index++] = 0x00;
    opciones[index++] = 0xff;
    memcpy(paqEnv+240,opciones,index);

    tam = sendto(udp_socket, paqEnv, 240+index, 0, (struct sockaddr*)&CLIENT, lrecv);
    return tam != -1 ? 0 : -1;
}

int main(){

    memset(ip_stored,0,IPS_MANAGED); //reset

    while(1) {
        udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

        if(udp_socket == -1){
            perror("\nError al abrir el socket");
            return -1;
        }

        struct ifreq ifr;
        memset(&ifr,0,sizeof(ifr));
        snprintf(ifr.ifr_name,sizeof(ifr.ifr_name),"eth0");
        if(setsockopt(udp_socket,SOL_SOCKET,SO_BINDTODEVICE,(void*)&ifr,sizeof(ifr)) < 0) {
            close(udp_socket);
            return 0;
        }

        int broadcast = 1;
        if(setsockopt(udp_socket,SOL_SOCKET,SO_BROADCAST,&broadcast,sizeof(broadcast)) < 0) {
            close(udp_socket);
            return 0;
        }

        printf("\nExito al abrir el socket\n");
        SERVER.sin_family = AF_INET;
        SERVER.sin_port   = htons(SERVER_PORT);
        SERVER.sin_addr.s_addr = INADDR_ANY;
        lbind = bind(udp_socket, (struct sockaddr*)&SERVER, sizeof(SERVER));
        if(lbind == -1) {
            perror("\nError en bind");
            return -1;
        }

        CLIENT.sin_family = AF_INET;
        CLIENT.sin_port   = htons(CLIENT_PORT);
        CLIENT.sin_addr.s_addr = INADDR_BROADCAST;

        char type[1];
        int discover = DHCP_Discover();
        for(int i=0; i<sizeof(dictionary)/12;i++)
            if(!memcmp(mac,dictionary[i][1],1))
                strcpy(type,dictionary[i][0]);

        int offer    = discover==0?DHCP_Offer(type):-1;
        int request  = offer==0?DHCP_Request():-1;
        int ack      = request==0?DHCP_Ack():-1;

        printf("DHCP Discover ==> %s\n",discover==0?"recibido":"fallido");  //  <--
        printf("DHCP Offer    ==> %s\n",offer==0?"enviado":"fallido");      //  -->
        printf("DHCP Request  ==> %s\n",request==0?"recibido":"fallido");   //  <--
        printf("DHCP ACK      ==> %s\n",ack==0?"enviado":"fallido");        //  -->

        close(udp_socket);
    }
    return 0;
}
