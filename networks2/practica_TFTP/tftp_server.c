#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>

#define APP_NAME 20

/************************/
// Author: Victor Franco
// Date:   03/21/2022
/************************/

void showBytes(unsigned char block[]) {
    for (int i=0; i<512; i++) {
        if(i%16 == 0) printf("\n");
        if(i%8 == 0)  printf("    ");
        printf("0x%02x ", block[i]);
    }
}

void intTochars(unsigned int num,unsigned char numArray[2]) {
    numArray[0] = (num&0xFF00)>>8;
    numArray[1] = num&0x00FF;
}

unsigned int charsToInt(unsigned char*string, int tam) {
    unsigned int result = 0;
    for(int i=0; i<tam; i++) {
        result = result<<8;
        result += string[i];
    }
    return result;
}

int subir(unsigned char nombre[APP_NAME],int udp_socket,struct sockaddr_in CLIENTE) {
    unsigned char codLec[2] = {0x00,0x04}; // ACK
    unsigned char msj[516], paqRec[512+4];
    FILE *archivo2 = fopen ( nombre , "wb" ); // open or overwrite file to save bytes
    int tam, tam2, lrecv;
    unsigned char block[2];
    struct timeval start, end;
    long mtime, seconds,useconds;
    unsigned int counter = 0;
    memset(paqRec, 0, 516);
    lrecv = sizeof(CLIENTE);
    do {
        tam   = 0;
        mtime = 0;
        gettimeofday(&start, NULL);
        while(mtime < 5000){
            if(mtime%1000 == 0 && tam != -1 || tam != -1 && charsToInt(paqRec+2,2) == counter) {
                intTochars(counter, block);
                memcpy(msj+0, codLec, 2);//-------------------|--> ACK
                memcpy(msj+2, block, 2); //                   |--> block
                tam2 = sendto(udp_socket, msj, 4, 0, (struct sockaddr*)&CLIENTE, sizeof(CLIENTE));
                if(tam2 == -1){          //                   |
                    perror("\nError al enviar");//            |
                    return -1;           //-------------------|
                }
            }

            tam = recvfrom(udp_socket, paqRec, 512+4, MSG_DONTWAIT, (struct sockaddr*)&CLIENTE, &lrecv);
            if(tam != -1 && paqRec[1] == 0x03 && charsToInt(paqRec+2,2) == counter+1) {//--|--> DATA
                fwrite ( paqRec+4, 1, tam-4, archivo2 );                  //--|--> save data into file copy
                break;
            }

            gettimeofday(&end, NULL);              //-------------------|
            seconds  = end.tv_sec  - start.tv_sec; //                   |--> time
            useconds = end.tv_usec - start.tv_usec;//                   |
            mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;//-------|
        }
        counter++;
    } while(tam == 512+4);
    intTochars(counter, block);
    memcpy(msj+0, codLec, 2);//-------------------|--> ACK
    memcpy(msj+2, block, 2); //                   |--> block
    tam2 = sendto(udp_socket, msj, 4, 0, (struct sockaddr*)&CLIENTE, sizeof(CLIENTE));
    if(tam2 == -1){          //                   |
        perror("\nError al enviar");//            |
        return -1;           //-------------------|
    }
    return 0;
}

int descargar(unsigned char nombre[APP_NAME],int udp_socket,struct sockaddr_in CLIENTE) {
    unsigned char codLec[2] = {0x00,0x03}; // DATA
    unsigned char msj[516], paqRec[512+4];
    FILE *archivo1 = fopen ( nombre , "rb" ); // open the file to extract bytes
    unsigned char block[2] = {0x00,0x01};     // counter
    int tam, tam2, lrecv;
    unsigned char informacion[512];
    struct timeval start, end;
    long mtime, seconds,useconds;
    unsigned int counter = 1;
    if(!archivo1) {
        printf("El archivo no existe");
        return -1;
    }
    lrecv = sizeof(CLIENTE);
    while ( !feof( archivo1 ) ) {
        tam   = 0;
        mtime = 0;
        gettimeofday(&start, NULL);
        int cantidad = fread ( informacion, 1, sizeof(informacion), archivo1 );// extract bytes from file
        while(mtime < 5000){
            if(mtime%1000 == 0 && tam != -1) {
                intTochars(counter, block);
                memcpy(msj+0, codLec, 2);  //-----------------|--> DATA
                memcpy(msj+2, block, 2);   //                 |--> block
                memcpy(msj+4, informacion, cantidad);//       |--> send message
                tam2 = sendto(udp_socket, msj, cantidad+4, 0, (struct sockaddr*)&CLIENTE, sizeof(CLIENTE));
                if(tam2 == -1){            //                 |
                    perror("\nError al enviar");//            |
                    return -1;             //                 |
                }                          //-----------------|
                memset(msj, 0, 516);
            }

            tam = recvfrom(udp_socket, paqRec, 4, MSG_DONTWAIT, (struct sockaddr*)&CLIENTE, &lrecv);
            if(tam != -1 && paqRec[1] == 0x04 && charsToInt(paqRec+2,2) == counter) break;//--|--> ACK

            gettimeofday(&end, NULL);              //-------------------|
            seconds  = end.tv_sec  - start.tv_sec; //                   |--> time
            useconds = end.tv_usec - start.tv_usec;//                   |
            mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;//-------|
        }
        counter++;
    }
    return 0;
}

int tftp_server() {
    struct sockaddr_in SERVIDOR, CLIENTE;
    unsigned char msj[516], paqRec[512+4];
    unsigned char nombre[APP_NAME];
    int  udp_socket, lbind, tam, tam2, lrecv, tammsj;

    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);//-----------------|--> open socket
    if (udp_socket == -1) {                     //                 |
        perror("\nError al abrir el socket");   //                 |
        return -1;                              //                 |
    }                                           //                 |
    perror("\nExito al abrir el socket");       //-----------------|

    SERVIDOR.sin_family = AF_INET;              //-----------------|--> config server
    SERVIDOR.sin_port   = htons(1069);          //                 |
    SERVIDOR.sin_addr.s_addr = INADDR_ANY;      //                 |
    lbind = bind(udp_socket, (struct sockaddr*)&SERVIDOR, sizeof(SERVIDOR));
    if(lbind == -1) {                           //                 |
        perror("\nError en bind");              //                 |
        return -1;                              //                 |
    }                                           //                 |
    perror("\nExito en bind");                  //-----------------|
    printf("\nEsperando...\n");

    lrecv = sizeof(CLIENTE);                    //-----------------|--> wait for client
    tam   = recvfrom(udp_socket, paqRec, 512+4, 0, (struct sockaddr*)&CLIENTE, &lrecv);
    if(tam == -1){                              //                 |
        perror("\nError de la solicitud");      //                 |
        return -1;                              //                 |
    }                                           //-----------------|
    perror("\nProcesando");

    memcpy(nombre, paqRec+2, strlen(paqRec+2));
    int result = 0;
    switch(paqRec[1]) {
        case 0x01: result = descargar(nombre,udp_socket,CLIENTE); break;
        case 0x02: result = subir(nombre,udp_socket,CLIENTE);     break;
    }
    close(udp_socket);
    return result;
}

int main() {
    printf("-------------------\n"
           "     Servidor      \n"
           "-------------------\n");
    return tftp_server();
}
