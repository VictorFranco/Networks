#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

/************************/
// Author: Victor Franco
// Date:   05/02/2022
/************************/

int udp_socket_buscar,udp_socket, lbind, tam, lrecv;
struct sockaddr_in SERVIDOR, CLIENTE, local, remota;
unsigned char msg[512], paqRec[512];
pthread_t hilo1, hilo2;

char*white_list[] = {
    /*      DNS navegador        */
    "clientservices.googleapis.com",
    "encrypted-tbn0.gstatic.com",
    "lh5.googleusercontent.com",
    "www.gstatic.com",
    "accounts.google.com",
    "update.googleapis.com",
    "optimizationguide-pa.googleapis.com",
    "safebrowsing.googleapis.com",
    "apis.google.com",
    "mtalk.google.com",
    "adservice.google.com",

    /*          Google           */
    "www.google.com",
    "google.com",

    /*            IPN            */
    "www.ipn.mx",
    "ipn.mx",
    "framework-gb.cdn.gob.mx",
    "dev.desarrolloweb.ipn.mx",
    "www.dev.desarrolloweb.ipn.mx",
    "cdnjs.cloudflare.com",
    "code.jquery.com",
    "load.sumo.com",
    "sumo.com",
    "content-autofill.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",

    /*          GITHUB           */
    "github.com",
    "github.githubassets.com",
    "avatars.githubusercontent.com",
    "users-images.githubusercontent.com",
    "github-cloud.s3.amazonaws.com",
    "api.github.com",
    "user-images.githubusercontent.com",
    "collector.github.com",

    /*          MEET           */
    "meet.google.com",
    "apps.google.com",
    "accounts.google.com",
    "play.google.com",
    "www.googletagmanager.com",
    "safebrowsing.googleapis.com",
    "lh3.googleusercontent.com",
    "optimitationguide-pa.googleapis.com",
    "ssl.gstatic.com",
    "accounts.youtube.com",
    "signaler-pa.googleapis.com",
    "www.googleapis.com",
    "clients4.google.com",
    "android.clients.google.com",
    "clients6.google.com",
    "scone-pa.clients6.google.com",
    "meetings.googleapis.com",
    "signaler-pa.clients6.google.com",
    "redirector.gvt1.com",
    "meetings.clients6.google.com",
    "hangouts.clients6.google.com",
    "clients2.google.com",
};

void showBytes(unsigned char*block,int len) {
    for (int i=0; i<len; i++) {
        if(i%16 == 0) printf("\n");
        if(i%8 == 0)  printf("    ");
        printf("0x%02x ", block[i]);
    }
}

unsigned int charsToInt(unsigned char*string, int tam) {
    unsigned int result = 0;
    for(int i=0; i<tam; i++) {
        result  = result << 8;
        result += string[i];
    }
    return result;
}

// recursive function that gets the url string and returns the size of the string
unsigned int getNombreDePeticion(unsigned int index,unsigned char paqRec[512],unsigned char*name) {
    unsigned char current_byte = paqRec[index];
    unsigned char counter_bytes = 0;
    int is_first_char = 1;
    unsigned char*pname = name;
    memset(name,0,sizeof(*name));
    while(paqRec[index]!=0x00) {
        if(paqRec[index]>>6 == 0b11) {
            int num = charsToInt(paqRec+index,2);
            int pointer = num-(0b11<<14);
            !is_first_char && (*pname++ = '.');
            getNombreDePeticion(pointer,paqRec,pname);
            counter_bytes = 0;
            index += 2;
            break;
        }
        if(current_byte == counter_bytes-1) {
            *pname++ = '.';
            current_byte = paqRec[index];
            counter_bytes = 0;
        }
        else !is_first_char && (*pname++ = paqRec[index]);
        counter_bytes++;
        index++;
        is_first_char = 0;
    }
    *pname = '\0';
    return index;
}

int redirect(int sizeName) {                // send a message with the ip of the other page
    memset(msg,0,512);
    memcpy(msg,paqRec,2);                   // id
    unsigned char banderas[] = {0x80,0x00};
    memcpy(msg+2,banderas,2);
    unsigned char num_pet[] = {0x00,0x01};
    memcpy(msg+4,num_pet,2);
    unsigned char num_rec_res[] = {0x00,0x01};
    unsigned char num_rec_aut[] = {0x00,0x00};
    unsigned char num_rec_adc[] = {0x00,0x00};
    memcpy(msg+6, num_rec_res, 2);
    memcpy(msg+8, num_rec_aut, 2);
    memcpy(msg+10,num_rec_adc, 2);
    memcpy(msg+12,paqRec+12,sizeName-12);
    unsigned char tipo_peticion[]  = {0x00,0x01};
    unsigned char clase_internet[] = {0x00,0x01};
    memcpy(msg+14+sizeName-13,tipo_peticion, 2);
    memcpy(msg+16+sizeName-13,clase_internet, 2);
    unsigned char pointer[] = {0xc0,0x0c};
    memcpy(msg+18+sizeName-13,pointer,2);
    memcpy(msg+20+sizeName-13,tipo_peticion, 2);
    memcpy(msg+22+sizeName-13,clase_internet, 2);
    char TTL[] = {0x00,0x00,0x07,0x08};
    memcpy(msg+24+sizeName-13,TTL,4);
    unsigned char length[] = {0x00,0x04};
    memcpy(msg+28+sizeName-13,length,2);
    unsigned char ip[] = {192,168,1,70};    // define http server ip
    memcpy(msg+30+sizeName-13,ip,4);
    tam=sendto(udp_socket,msg,34+sizeName-13,0,(struct sockaddr *)&CLIENTE,sizeof(CLIENTE));
    return tam != -1 ? 0 : -1;
}

int allowComunication(int tam) {
    struct timeval start, end;
    long mtime = 0, seconds,useconds;
    int tam2,tam3,lrecv2;

    memset(msg,0,512);
    memcpy(msg,paqRec,tam);         // send request from proxy client to DNS server
    tam2 = sendto(udp_socket_buscar,msg,tam,0, (struct sockaddr*)&remota, sizeof(remota));
    if(tam2 == -1){
        perror("\nError en envio");
        return -1;
    }
    do {
        lrecv2 = sizeof(remota);
        gettimeofday(&start, NULL); // receive message from DNS server
        tam2 = recvfrom(udp_socket_buscar,msg,512,MSG_DONTWAIT, (struct sockaddr*)&remota, &lrecv2);
        if(tam2 != -1) {            // send DNS server response to proxy client
            tam3 = sendto(udp_socket,msg,tam2,0, (struct sockaddr*)&CLIENTE, sizeof(CLIENTE));
            break;
        }
        gettimeofday(&end, NULL);              //-------------------|
        seconds  = end.tv_sec  - start.tv_sec; //                   |--> time
        useconds = end.tv_usec - start.tv_usec;//                   |
        mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;//-------|
    } while(mtime < 500);
    return 0;
}

int main(){

    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if(udp_socket == -1){
        perror("\nError al abrir el socket");
        return -1;
    }

    system("clear");
    perror("\nExito al abrir el socket");
    SERVIDOR.sin_family = AF_INET;
    SERVIDOR.sin_port   = htons(53);
    SERVIDOR.sin_addr.s_addr = INADDR_ANY;
    lbind = bind(udp_socket, (struct sockaddr*)&SERVIDOR, sizeof(SERVIDOR));
    if(lbind == -1){
        perror("\nError en bind");
        return -1;
    }
    perror("\nExito en bind servidor proxy");

    udp_socket_buscar = socket(AF_INET,SOCK_DGRAM,0);
    if(udp_socket_buscar == -1){
        perror("\nError al abrir el socket");
        return -1;
    }

    local.sin_family = AF_INET;
    local.sin_port   = htons(0);
    local.sin_addr.s_addr = INADDR_ANY;
    lbind = bind(udp_socket_buscar, (struct sockaddr*)&local, sizeof(local));
    if(lbind == -1){
        perror("\nError en bind");
        return -1;
    }
    remota.sin_family = AF_INET;
    remota.sin_port   = htons(53);
    remota.sin_addr.s_addr = inet_addr("8.8.8.8");  // DNS server ip

    perror("\nExito en bind servidor DNS");

    printf("\nEspera a que envien un mensaje\n\n");

    while(1) {
        lrecv = sizeof(CLIENTE);
        tam   = recvfrom(udp_socket, paqRec, 512, 0, (struct sockaddr*)&CLIENTE, &lrecv);
        if(tam == -1){
            perror("\nError al recibir");
            exit(0);
        }
        unsigned char*pointer = paqRec;
        pointer += 2;
        if(!(*pointer>>7)) { // if the message is a request
            unsigned char url[100];
            int sizeName = getNombreDePeticion(12,paqRec,url);
            int i,check=0;
            printf("%s ",url);
            for(int i=0; i<sizeof(white_list)/sizeof(char*); i++)
                if(!memcmp(white_list[i],url,strlen(white_list[i]))) check = 1;
            printf("%s\n",check ? "ok" : "x");
            check ? allowComunication(tam) : redirect(sizeName);
        }
    }
    close(udp_socket_buscar);
    close(udp_socket);
    return 0;
}
