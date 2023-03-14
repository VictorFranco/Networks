#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <pthread.h>//hilos
int udp_socket,lbind,tam,lrecv;
struct sockaddr_in CLIENTE;
unsigned char msj[100]="hola";
unsigned char paqRec[512];
struct sockaddr_in SERVIDOR;
pthread_t hilo1;
pthread_t hilo2;

unsigned char registro[1000];

void recarga(){
    system("clear");
    printf("%s",registro);
}
void *mandar(void *datos){
    while(memcmp(msj,"bye",3)!=0){
        fgets(msj,100,stdin);
        tam=sendto(udp_socket,msj,strlen(msj)+1,0,(struct sockaddr*)&CLIENTE,sizeof(CLIENTE));
        if(tam==-1){
            perror("\nError al enviar");
            exit(0);
        }else{
            strcat(registro,"<<< ");
            strcat(registro,msj);
            strcat(registro,"\n");
            recarga();
            perror("---------------->Exito al enviar");
            printf("\n");
        }
    }
    pthread_cancel(hilo1);
}
void *escuchar(void *datos){
    while(1){
        lrecv=sizeof(CLIENTE);
        tam=recvfrom(udp_socket,paqRec,512,0,(struct sockaddr*)&CLIENTE,&lrecv);
        if(tam==-1){
            perror("\nError al recibir");
            exit(0);
        }else{
            printf("|--->>> %s\n",paqRec);
            strcat(registro,"--->>> ");
            strcat(registro,paqRec);
            strcat(registro,"\n");
        }
    }
}
int main(){
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_socket==-1){
        perror("\nError al abrir el socket");
        exit(0);
    }else{
        system("clear");
        perror("\nExito al abrir el socket");
        SERVIDOR.sin_family=AF_INET; /* address family: AF_INET */
        SERVIDOR.sin_port=htons(8080);   /* port in network byte order */
        SERVIDOR.sin_addr.s_addr=INADDR_ANY;   /* internet address */
        lbind=bind(udp_socket,(struct sockaddr*)&SERVIDOR,sizeof(SERVIDOR));
        if(lbind==-1){
               perror("\nError en bind");
            exit(0);
        }else{
            perror("\nExito en bind");
            printf("\nEspera a que envien un mensaje\n\n");

            strncpy(registro,"",strlen(registro));

            pthread_create(&hilo1,NULL,&escuchar,"");
            pthread_create(&hilo2,NULL,&mandar,"");

        }
    }
    pthread_join(hilo1,NULL);
    pthread_join(hilo2,NULL);
    close(udp_socket);
    return 0;
}
