#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/time.h>

/************************/
// Author: Victor Franco
// Date:   04/14/20
/************************/

void showBytes(unsigned char*block,int len) {
    for (int i=0; i<len; i++) {
        i%16 == 0 && printf("\n");
        i%8  == 0 && printf("    ");
        printf("0x%02x ", block[i]);
    }
    printf("\n");
}

int enviarUDP(int udp_socket,struct sockaddr_in remota,char*url) {
    int tam;
    unsigned char msj[512];
    unsigned char id[] = {0x01,0x01};
    //1/0 res/sol   4 codigo operacion    1/0 respuesta autoriada 1/0 truncado 1/0 recursion
    //     0        0000 solicitud directa          0 x                0  x         1 
    //1/0 recursion realizada  3 reservado   4 codigo retorno
    //     0  x                    000             0000  x
    unsigned char banderas[] = {0b00000001,0b00000000};
    unsigned char num_pet[] = {0x00,0x01};
    unsigned char num_rec_res[] = {0x00,0x00}; // x
    unsigned char num_rec_aut[] = {0x00,0x00}; // x
    unsigned char num_rec_adc[] = {0x00,0x00}; // x
    // entrada de solicitud dns
    unsigned char nom_peticion[strlen(url)+2];
    // 0x01 registro host 0x02 registro A servidor de nombres 0x05 registro alias 0x0c registro de busqueda inversa
    unsigned char tipo_peticion[]  = {0x00,0x01};
    unsigned char clase_internet[] = {0x00,0x01};
    memcpy(msj+0, id, 2);
    memcpy(msj+2, banderas, 2);
    memcpy(msj+4, num_pet, 2);
    memcpy(msj+6, num_rec_res, 2);
    memcpy(msj+8, num_rec_aut, 2);
    memcpy(msj+10,num_rec_adc, 2);

    memset(nom_peticion,0, strlen(url)+2);
    unsigned char aux2 = 0;
    unsigned char counter = 0;
    for(int i=0; i<strlen(url); i++) {
        if(url[i] != '.') {
            nom_peticion[i+1] = url[i];
            counter++;
        }
        if(url[i] == '.' || i == strlen(url)-1) {
            nom_peticion[aux2] = counter;
            counter = 0;
            aux2 = i+1;
        }
    }
    nom_peticion[strlen(url)+1] = 0x00;

    memcpy(msj+12,nom_peticion,strlen(url)+2);
    memcpy(msj+14+strlen(url),tipo_peticion, 2);
    memcpy(msj+16+strlen(url),clase_internet, 2);

    tam=sendto(udp_socket,msj,18+strlen(url),0,(struct sockaddr *)&remota,sizeof(remota));

    if(tam == -1) {
        perror("\nError al enviar");
        return -1;
    }
    else perror("\nExito al enviar");

    showBytes(msj,35);
    return 0;
}

unsigned int charsToInt(unsigned char*string, int tam) {
    unsigned int result = 0;
    for(int i=0; i<tam; i++) {
        result  = result << 8;
        result += string[i];
    }
    return result;
}

unsigned int getNombreDePeticion(unsigned int index,unsigned char paqRec[512]) {
    unsigned char current_byte = paqRec[index];
    unsigned char counter_bytes = 0;
    int is_first_char = 1;
    while(paqRec[index]!=0x00) {
        if(paqRec[index]>>6 == 0b11) {
            int num = charsToInt(paqRec+index,2);
            int pointer = num-(0b11<<14);
            !is_first_char && printf(".");
            getNombreDePeticion(pointer,paqRec);
            counter_bytes = 0;
            index += 2;
            break;
        }
        if(current_byte == counter_bytes-1) {
            printf(". ");
            current_byte = paqRec[index];
            counter_bytes = 0;
        }
        else printf("%c ",paqRec[index]);
        counter_bytes++;
        index++;
        is_first_char = 0;
    }
    return index;
}

void titulo(char*titulo) {
    for(int i=0; i<40; i++) printf("-");
    printf("\n");
    printf("=> %s\n",titulo);
    for(int i=0; i<40; i++) printf("-");
    printf("\n");
}

char*codigo_operacion[] = {"Solicitud Directa","Solicitud Inversa","Solicitud del Estado del Servidor"};
char*tipo_peticion[] = {"","Registro Host","Nombre del servidor de autoridad","","","CNAME"};

int recibirUDP(int udp_socket,struct sockaddr_in remota) {
    int tam = 0;
    struct timeval start, end;
    long mtime, seconds, useconds;
    unsigned char paqRec[512];
    int lrecv = sizeof(remota);
    memset(paqRec, 0, 512);
    mtime=0;
    gettimeofday(&start, NULL);
    while(mtime<5000) {
        tam = recvfrom(udp_socket, paqRec, 512, MSG_DONTWAIT, (struct sockaddr*)&remota, &lrecv);
        gettimeofday(&end, NULL);
        seconds  = end.tv_sec  - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;
        mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
        if(tam != -1) break;
    }
    if(tam == -1) {
        perror("Error al recibir");
        return -1;
    }
    titulo("Analisis de respuesta");
    printf("id = 0x%02x 0x%02x\n",paqRec[0],paqRec[1]);
    unsigned char banderas[] = {paqRec[2],paqRec[3]};
    printf("banderas = 0x%02x 0x%02x\n",banderas[0],banderas[1]);
    printf("%x => %s\n",banderas[0]>>7,banderas[0]&0b10000000?"Respuesta":"Solicitud");
    printf("%x => codigo operacion: %s\n",(banderas[0]>>3)&0b1111,codigo_operacion[(banderas[0]>>3)&0b1111]);
    printf("%x => %s\n",(banderas[0]&0b100)>1,banderas[0]&0b100?"Es autoridad":"No es autoridad");
    printf("%x => %s\n",(banderas[0]&0b10)>1,banderas[0]&0b10?"Fue truncado":"No fue truncado");
    printf("%x => %s\n",banderas[0]&0b1,banderas[0]&0b1?"Recursion usada":"Sin usar recursion");

    printf("%x => %s\n",banderas[1]>>7,banderas[1]&0b10000000?"Recursion Disponible":"Recursion No Disponible");
    printf("%x => codigo retorno: %s\n",banderas[1]&0b1111,(banderas[1]&0b1111) == 0?"Respuesta correcta":"Error de nombres");

    int num[3];
    num[0] = charsToInt(paqRec+6,2);
    printf("%d registros de recurso de respuesta\n",num[0]);
    num[1] = charsToInt(paqRec+8,2);
    printf("%d registros de recurso de autoridad\n",num[1]);   num[1] += num[0];
    num[2] = charsToInt(paqRec+10,2);
    printf("%d registros de recurso de adicionales\n",num[2]); num[2] += num[1];
    /*************** Entrada *****************/
    unsigned int index = 12;
    titulo("Entrada");
    printf("Nombre de peticion => ");
    index = getNombreDePeticion(index,paqRec);
    printf("\n");
    printf("tipo de peticion: %s\n",tipo_peticion[charsToInt(paqRec+index+1,2)]);
    printf("clase: %s\n",charsToInt(paqRec+index+3,2) == 1?"Internet":"");
    if((banderas[1]&0b1111) == 5) return -1;
    /*****************************************/
    index+=5;
    int counter=0;
    for(int i=0; i<num[2]; i++) {
        (i == 0 || i == num[0] || i == num[1]) && printf("\n\n");
        if(num[0] > i)      titulo("Registro de recurso de respuesta");
        else if(num[1] > i) titulo("Registro de recurso de autoridad");
        else if(num[2] > i) titulo("Registro de recurso de adicionales");
        printf("Nombre de peticion => ");
        index = getNombreDePeticion(index,paqRec);
        printf("\n");
        printf("Tipo de peticion: %s\n",tipo_peticion[charsToInt(paqRec+index,2)]);
        printf("Clase: %s\n",charsToInt(paqRec+index+2,2) == 1?"Internet":"");
        printf("TTL: %d seg\n",charsToInt(paqRec+index+4,4));
        int length = charsToInt(paqRec+index+8,2);
        printf("length: %d\n",length);
        switch (length) {
            case 4:
                printf("ip: "); // mostrar una ipv4
                for(int i=0; i<length; i++) printf("%d%s",paqRec[index+10+i],i<length-1?".":"");
                printf("\n");
                break;
            case 16:
                printf("ip: "); // mostrar una ipv6
                for(int i=0; i<length; i++) printf("%02x ",paqRec[index+10+i]);
                printf("\n");
                break;
            default:            // mostrar nombre servidor
                printf("Nombre servidor => ");
                getNombreDePeticion(index+10,paqRec);
                printf("\n");
                break;
        }
        index = index+10+length;
    }
    return 0;
}

int main(int argc,char *argv[]) {
    int udp_socket, lbind, tam;
    struct sockaddr_in local, remota;
    udp_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (udp_socket == -1) {
        perror("\nError al abrir el socket");
        return -1;
    }

    perror("\nExito al abrir el socket");
    local.sin_family = AF_INET;
    local.sin_port   = htons(0);
    local.sin_addr.s_addr = INADDR_ANY;
    lbind = bind(udp_socket,(struct sockaddr*)&local,sizeof(local));

    if(lbind == -1) {
        perror("\nError en bind");
        return -1;
    }

    perror("\nExito en bind");
    remota.sin_family = AF_INET;
    remota.sin_port   = htons(53);
    remota.sin_addr.s_addr = inet_addr(argv[1]);

    enviarUDP(udp_socket,remota,argv[2]);
    printf("\n");

    recibirUDP(udp_socket,remota);

    close(udp_socket);
    return 0;
}
