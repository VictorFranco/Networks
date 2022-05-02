#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#define SERVER_PORT 8080
#define PACK_SIZE   512
#define SERVER_IP   "192.168.1.69"

struct sockaddr_in local, remote;
unsigned char msg[PACK_SIZE], paqRec[PACK_SIZE];
char buffer[10000];
int udp_socket, lbind, tam;
socklen_t lrecv;
pthread_t thread1, thread2;

void refresh(){
    system("clear");
    printf("%s", buffer);
}

void *send_messages(void *args){
    lrecv = sizeof(remote);
    while(memcmp(msg, "bye", 3) != 0){
        fgets((char*)msg, PACK_SIZE, stdin);
        tam = sendto(udp_socket, msg, strlen((char*)msg)+1, 0, (struct sockaddr*)&remote, lrecv);
        if(tam == -1){
            perror("\nError al enviar");
            exit(0);
        }
        strcat(buffer, "<<< ");
        strcat(buffer, (char*)msg);
        strcat(buffer, "\n");
        refresh();
        perror("---------------->Exito al enviar");
        printf("\n");
    }
    pthread_cancel(thread1);
    return NULL;
}

void *listen_messages(void *args){
    lrecv = sizeof(remote);
    while(memcmp(paqRec, "bye", 3) != 0){
        tam   = recvfrom(udp_socket, paqRec, PACK_SIZE, 0, (struct sockaddr*)&remote, &lrecv);
        if(tam == -1){
            perror("\nError al recibir");
            exit(0);
        }
        printf("|--->>> %s\n", paqRec);
        strcat(buffer, "--->>> ");
        strcat(buffer, (char*)paqRec);
        strcat(buffer, "\n");
    }
    pthread_cancel(thread2);
    return NULL;
}

int main(){
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if(udp_socket == -1){
        perror("\nError al abrir el socket");
        return -1;
    }

    system("clear");
    perror("\nExito al abrir el socket");
    local.sin_family = AF_INET;
    local.sin_port   = htons(0);
    local.sin_addr.s_addr = INADDR_ANY;
    lbind = bind(udp_socket, (struct sockaddr*)&local, sizeof(local));

    if(lbind == -1){
        perror("\nError en bind");
        return -1;
    }

    perror("\nExito en bind");
    printf("\nEnvia un mensaje\n\n");
    remote.sin_family = AF_INET;
    remote.sin_port   = htons(SERVER_PORT);
    remote.sin_addr.s_addr = inet_addr(SERVER_IP);

    strcpy(buffer, "");

    pthread_create(&thread1, NULL, &listen_messages, "");
    pthread_create(&thread2, NULL, &send_messages, "");

    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    close(udp_socket);
    return 0;
}
