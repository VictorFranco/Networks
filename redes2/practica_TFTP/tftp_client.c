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

void showBytes(unsigned char*block,int len) {
    for (int i=0; i<len; i++) {
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

int descargar(unsigned char nombre[APP_NAME],int udp_socket,struct sockaddr_in remota) {
    unsigned char codLec[2] = {0x00,0x04}; // ACK
    unsigned char msj[516], paqRec[512+4];
    FILE *archivo2 = fopen ( nombre , "wb" ); // open or overwrite file to save bytes
    int tam, tam2, lrecv;
    unsigned char block[2];
    struct timeval start, end;
    long mtime, seconds,useconds;
    unsigned int counter = 1;
    lrecv = sizeof(remota);
    do {
        tam   = -1;
        mtime = 0;
        gettimeofday(&start, NULL);
        while(mtime < 5000 && tam == -1){
             // receive DATA
            tam   = recvfrom(udp_socket, paqRec, 512+4, MSG_DONTWAIT, (struct sockaddr*)&remota, &lrecv);

            if(tam != -1 && paqRec[1] == 0x03 && charsToInt(paqRec+2,2) == counter) {
                fwrite ( paqRec+4, 1, tam-4, archivo2 );//----|--> DATA
                memset(msj, 0, 516);      //-------------------|--> save data into file copy

                intTochars(counter, block);
                memcpy(msj+0, codLec, 2);//-------------------|
                memcpy(msj+2, block, 2); //                   |--> ACK
                tam2 = sendto(udp_socket, msj, 4, 0, (struct sockaddr*)&remota, sizeof(remota));
                if(tam2 == -1){          //                   |
                    perror("\nError al enviar");//            |
                    return -1;           //-------------------|
                }
                memset(paqRec, 0, 512+4);
                break;
            }

            if(tam != -1 && paqRec[1] == 0x05 || tam != -1 &&  charsToInt(paqRec+2,2) == counter-1) {
                intTochars(counter, block);//-----------------|--> Error / reintent ACK
                memcpy(msj+0, codLec, 2);  //                 |
                memcpy(msj+2, block, 2);   //                 |
                tam2 = sendto(udp_socket, msj, 4, 0, (struct sockaddr*)&remota, sizeof(remota));
                if(tam2 == -1){            //                 |
                    perror("\nError al enviar");//            |
                    return -1;             //-----------------|
                }
                memset(paqRec, 0, 512+4);
            }

            gettimeofday(&end, NULL);              //-------------------|
            seconds  = end.tv_sec  - start.tv_sec; //                   |--> time
            useconds = end.tv_usec - start.tv_usec;//                   |
            mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;//-------|
        }
        counter++;
    } while(tam == 516);
    return 0;
}

int subir(unsigned char nombre[APP_NAME],int udp_socket,struct sockaddr_in remota) {
    unsigned char codLec[2] = {0x00,0x03}; // DATA
    unsigned char msj[516], paqRec[512+4];
    FILE *archivo1 = fopen ( nombre , "rb" ); // open the file to extract bytes
    struct timeval start, end;
    long mtime, seconds,useconds;
    unsigned int counter = 0;
    int tam,tam2, lrecv;
    unsigned char block[2];
    char informacion[512];
    if(!archivo1) {
        printf("El archivo no existe");
        return -1;
    }
    lrecv = sizeof(remota);
    while ( !feof( archivo1 ) ) {
        tam   = -1;
        mtime = 0;
        gettimeofday(&start, NULL);
        int cantidad = fread ( informacion, 1, sizeof(informacion), archivo1 );
        memset(paqRec, 0, 512+4);
        while(mtime < 5000 && tam == -1){
            tam   = recvfrom(udp_socket, paqRec, 512+4, MSG_DONTWAIT, (struct sockaddr*)&remota, &lrecv);

            if(tam != -1 && paqRec[1] == 0x04 && charsToInt(paqRec+2,2) == counter) {
                intTochars(counter+1, block);//---------------|--> ACK
                memset(msj, 0, 50);        //-----------------|

                memcpy(msj+0, codLec, 2);  //-----------------|--> DATA
                memcpy(msj+2, block, 2);   //                 |--> block
                memcpy(msj+4, informacion, cantidad);//       |--> send message
                tam2 = sendto(udp_socket, msj, cantidad+4, 0, (struct sockaddr*)&remota, sizeof(remota));
                if(tam2 == -1){            //                 |
                    perror("\nError al enviar");//            |
                    return -1;             //                 |
                }                          //-----------------|
                memset(paqRec, 0, 512+4);
                break;
            }

            if(tam != -1 && paqRec[1] == 0x05 || tam != -1 && charsToInt(paqRec+2,2) == counter-1) {
                intTochars(counter+1, block);//---------------|--> Error / reintent DATA
                memcpy(msj+0, codLec, 2);//                   |
                memcpy(msj+2, block, 2); //                   |
                tam2 = sendto(udp_socket, msj, 4, 0, (struct sockaddr*)&remota, sizeof(remota));
                if(tam2 == -1){          //                   |
                    perror("\nError al enviar");//            |
                    return -1;           //-------------------|
                }
                memset(paqRec, 0, 512+4);
            }

            gettimeofday(&end, NULL);              //-------------------|
            seconds  = end.tv_sec  - start.tv_sec; //                   |--> time
            useconds = end.tv_usec - start.tv_usec;//                   |
            mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;//-------|
        }
        counter++;
    }
    recvfrom(udp_socket, paqRec, 512+4, 0, (struct sockaddr*)&remota, &lrecv);
    return 0;
}

int tftp_client(unsigned char codLec[2]) {
    struct sockaddr_in local, remota;
    unsigned char msj[516], paqRec[512+4];
    unsigned char modo[] = "octet";
    unsigned char nombre[APP_NAME];
    int  udp_socket, lbind, tam, tam2, lrecv, tammsj;
    struct timeval start, end;
    long mtime = 0, seconds,useconds;

    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);//-----------------|--> open socket
    if (udp_socket == -1) {                     //                 |
        perror("\nError al abrir el socket");   //                 |
        return -1;                              //                 |
    }                                           //                 |
    perror("\nExito al abrir el socket");       //-----------------|

    local.sin_family = AF_INET;                 //-----------------|--> config local
    local.sin_port   = htons(0);                //                 |
    local.sin_addr.s_addr = INADDR_ANY;         //                 |
    lbind = bind(udp_socket, (struct sockaddr*)&local, sizeof(local));
    if(lbind == -1) {                           //                 |
        perror("\nError en bind");              //                 |
        return -1;                              //                 |
    }                                           //                 |
    perror("\nExito en bind");                  //-----------------|

    remota.sin_family = AF_INET;                //-----------------|--> config remota
    remota.sin_port   = htons(1069);            //                 |
    remota.sin_addr.s_addr = inet_addr("192.168.1.71");//          |
    printf("\nInserta el nombre: ");            //-----------------|

    fgets(nombre, APP_NAME, stdin);             // request name
    nombre[strlen(nombre) - 1] = '\0';
    memcpy(msj+0, codLec, 2);                   // read or write
    memcpy(msj+2, nombre, strlen(nombre)+1);
    memcpy(msj+strlen(nombre)+3, modo, strlen(modo)+1);
    tammsj = strlen(nombre) + 4 + strlen(modo);

    do {
        if(mtime%1000 == 0)
            tam = sendto(udp_socket, msj, tammsj, 0, (struct sockaddr *)&remota, sizeof(remota));// send message
        tam2 = recvfrom(udp_socket, paqRec, 512+4, MSG_PEEK, (struct sockaddr*)&remota, &lrecv);
        if(tam2 != -1) break;
        gettimeofday(&end, NULL);              //-------------------|
        seconds  = end.tv_sec  - start.tv_sec; //                   |--> time
        useconds = end.tv_usec - start.tv_usec;//                   |
        mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;//-------|
    } while(mtime < 5000);

    if(paqRec[1] == 0x05){
        perror("\nSolicitud rechazada");
        return -1;
    }

    perror("\nSolicitud aceptada");
    int result = 0;
    switch(codLec[1]) {
        case 0x01: result = descargar(nombre,udp_socket,remota); break;
        case 0x02: result = subir(nombre,udp_socket,remota);     break;
    }
    close(udp_socket);
    return result;
}

int main() {
    char opcion[10];
    unsigned char codLec[2] = {0x00,0x00};
    printf("-------------------\n"
           "      Cliente      \n"
           "-------------------\n"//-------------------|
           "1) Descargar\n"       //                   |
           "2) Subir\n"           //                   |
           "==> ");               //                   |
    fgets(opcion, 10, stdin);     //                   |----> Menu
    switch(atoi(opcion)) {        //                   |
        case 1: codLec[1] = 0x01; break;//             |
        case 2: codLec[1] = 0x02; break;//             |
    }                                   //             |
    return tftp_client(codLec);//----------------------|
}
