#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#define SERVER_PORT 21
#define PACK_SIZE   1460
#define SERVER_IP   "192.168.1.67"

/**************************/
// Author: Victor Franco
// Date:   05/31/2022
/**************************/

unsigned char msg[PACK_SIZE];

int loggin(int tcp_socket) {
    memset(msg, 0, PACK_SIZE);
    printf("    User: ");
    strcpy(msg,"USER ");
    fgets(msg+strlen(msg), PACK_SIZE, stdin);
    msg[strlen(msg)-1] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);

    recv(tcp_socket, msg, PACK_SIZE, 0);
    char user_ok[] = {0x33,0x33,0x31};
    if(memcmp(msg,user_ok,3)!=0) {
        printf("Error in user\n");
        return -1;
    }

    memset(msg, 0, PACK_SIZE);
    printf("Password: ");
    strcpy(msg,"PASS ");
    fgets(msg+strlen(msg), PACK_SIZE, stdin);
    msg[strlen(msg)-1] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    printf("\n");

    recv(tcp_socket, msg, PACK_SIZE, 0);
    char pass_ok[] = {0x32,0x33,0x30};
    if(memcmp(msg,pass_ok,3)!=0) {
        printf("failed to loggin\n");
        return -1;
    }
    printf("User logged in\n");
    return 0;
}

int pwd(int tcp_socket) {
    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"PWD");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("server: %s",msg+4);
    return 0;
}

int ls(int tcp_socket) {
	int tcp_socket2,size_client2;
    struct sockaddr_in server2;

    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"PASV");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("server: %s",msg+4);

    char*token = strtok(msg+4,",");
    for(int i=0; i<3; i++) {
        token = strtok(NULL,",");
    }
    token = strtok(NULL,",");
    unsigned int port = atoi(token);
    port <<= 8;
    token = strtok(NULL,",");
    port += atoi(token);

    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"LIST");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("server: %s",msg+4);


    tcp_socket2 = socket(AF_INET,SOCK_STREAM,0);      //---------|---> open secondary socket
                                                      //         |
    if(tcp_socket2 == -1){                            //         |
        printf("Error: No se pudo crear el socket."); //         |
        return -1;                                    //         |
    }                                                 //---------|

    size_client2 = sizeof(server2);                   //---------|---> server info
    server2.sin_family = AF_INET;                     //         |
    server2.sin_port = htons(port);                   //         |
    server2.sin_addr.s_addr = inet_addr(SERVER_IP);   //---------|

    if(connect(tcp_socket2,(struct sockaddr*) &server2,sizeof(server2))==-1){
        printf("Error al conectarse con el servidor");
        return -1;
    }

    char buffer[20];
    int tam;                                              //--------|
    do {                                                  //        |
        memset(msg, 0, PACK_SIZE);                        //        |
        tam = recv(tcp_socket2, msg, PACK_SIZE, 0);       //        |
        printf("%s",msg);                                 //        |---> show information
    } while(recv(tcp_socket2, buffer, 20, MSG_PEEK) > 0); //        |
    close(tcp_socket2);                                   //--------|---> close secondary socket

    memset(msg, 0, PACK_SIZE);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("server: %s",msg+4);
    return 0;
}

int cd(int tcp_socket) {
    char folder[60];
    memset(msg, 0, PACK_SIZE);
    printf("Folder: ");
    strcpy(msg,"CWD ");
    fgets(folder,60,stdin);
    folder[strlen(folder)-1] = '\0';
    strcat(msg,folder);
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("\nserver: %s",msg+4);
    return 0;
}

int get(int tcp_socket) {
    char pass_mode[] = {0x32,0x32,0x37};
    char file_ok[] =   {0x31,0x35,0x30};
    char type_ok[] =   {0x32,0x30,0x30};
    char file[60];
	int tcp_socket2,size_client2,tam;
    FILE*f;
    struct sockaddr_in server2;

    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"TYPE I");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);

    recv(tcp_socket, msg, PACK_SIZE, 0);
    if(memcmp(msg,type_ok,3)!=0) {
        printf("Error in type mode\n");
        return -1;
    }

    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"PASV");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);

    recv(tcp_socket, msg, PACK_SIZE, 0);
    if(memcmp(msg,pass_mode,3)!=0) {
        printf("Error in set server mode\n");
        return -1;
    }

    char*token = token = strtok(msg+4,",");
    for(int i=0; i<3; i++) {
        token = strtok(NULL,",");
    }
    token = strtok(NULL,",");
    unsigned int port = atoi(token);
    port <<= 8;
    token = strtok(NULL,",");
    port += atoi(token);

    memset(msg, 0, PACK_SIZE);
    printf("File: ");
    strcpy(msg,"RETR ");
    fgets(file,60,stdin);
    file[strlen(file)-1] = '\0';
    strcat(msg,file);
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    printf("\n");

    recv(tcp_socket, msg, PACK_SIZE, 0);
    if(memcmp(msg,file_ok,3)!=0) {
        printf("Error file\n");
        return -1;
    }

    tcp_socket2 = socket(AF_INET,SOCK_STREAM,0);      //---------|---> open secondary socket
                                                      //         |
    if(tcp_socket2 == -1){                            //         |
        printf("Error: No se pudo crear el socket."); //         |
        return -1;                                    //         |
    }                                                 //---------|

    size_client2 = sizeof(server2);                   //---------|---> server info
    server2.sin_family = AF_INET;                     //         |
    server2.sin_port = htons(port);                   //         |
    server2.sin_addr.s_addr = inet_addr(SERVER_IP);   //---------|

    if(connect(tcp_socket2,(struct sockaddr*) &server2,sizeof(server2))==-1){
        printf("Error al conectarse con el servidor");
        return -1;
    }

    char buffer[20];
    f=fopen(file,"wb");                                  //----------|
    do {                                                 //          |
        memset(msg, 0, PACK_SIZE);                       //          |
        tam = recv(tcp_socket2, msg, PACK_SIZE, 0);      //          |
        fwrite(msg,1,tam,f);                             //          |---> save information
    } while(recv(tcp_socket2, buffer, 20, MSG_PEEK) > 0);//          |
    fclose(f);                                           //          |
    close(tcp_socket2);                                  //----------|---> close secondary socket

    memset(msg, 0, PACK_SIZE);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("server: %s",msg+4);
    return 0;
}

int put(int tcp_socket) {
    char pass_mode[] = {0x32,0x32,0x37};
    char file_ok[] =   {0x31,0x35,0x30};
    char type_ok[] =   {0x32,0x30,0x30};
    char file[60];
	int tcp_socket2,size_client2,tam;
    FILE*f;
    struct sockaddr_in server2;

    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"TYPE I");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);

    recv(tcp_socket, msg, PACK_SIZE, 0);
    if(memcmp(msg,type_ok,3)!=0) {
        printf("Error in type mode\n");
        return -1;
    }

    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"PASV");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);

    recv(tcp_socket, msg, PACK_SIZE, 0);
    if(memcmp(msg,pass_mode,3)!=0) {
        printf("Error in set server mode\n");
        return -1;
    }

    char*token = token = strtok(msg+4,",");
    for(int i=0; i<3; i++) {
        token = strtok(NULL,",");
    }
    token = strtok(NULL,",");
    unsigned int port = atoi(token);
    port <<= 8;
    token = strtok(NULL,",");
    port += atoi(token);

    memset(msg, 0, PACK_SIZE);
    printf("File: ");
    strcpy(msg,"STOR ");
    fgets(file,60,stdin);
    file[strlen(file)-1] = '\0';
    strcat(msg,file);
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    printf("\n");

    recv(tcp_socket, msg, PACK_SIZE, 0);
    if(memcmp(msg,file_ok,3)!=0) {
        printf("Error file\n");
        return -1;
    }

    tcp_socket2 = socket(AF_INET,SOCK_STREAM,0);      //---------|---> open secondary socket
                                                      //         |
    if(tcp_socket2 == -1){                            //         |
        printf("Error: No se pudo crear el socket."); //         |
        return -1;                                    //         |
    }                                                 //---------|

    size_client2 = sizeof(server2);                   //---------|---> server info
    server2.sin_family = AF_INET;                     //         |
    server2.sin_port = htons(port);                   //         |
    server2.sin_addr.s_addr = inet_addr(SERVER_IP);   //---------|

    if(connect(tcp_socket2,(struct sockaddr*) &server2,sizeof(server2))==-1){
        printf("Error al conectarse con el servidor");
        return -1;
    }

    f=fopen(file,"rb");                 //----------|
    memset(msg, 0, PACK_SIZE);          //          |
    tam = fread(msg,1,PACK_SIZE,f);     //          |
    while(tam==PACK_SIZE) {             //          |
        send(tcp_socket2, msg, tam, 0); //          |
        memset(msg, 0, PACK_SIZE);      //          |
        tam = fread(msg,1,PACK_SIZE,f); //          |
    }                                   //          |
    send(tcp_socket2, msg, tam, 0);     //          |---> send information
                                        //          |
    fclose(f);                          //          |
    close(tcp_socket2);                 //----------|---> close secondary socket

    memset(msg, 0, PACK_SIZE);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("server: %s",msg+4);
    return 0;
}

int quit(int tcp_socket) {
    memset(msg, 0, PACK_SIZE);
    strcpy(msg,"quit");
    msg[strlen(msg)] = 0x0d;
    msg[strlen(msg)] = 0x0a;
    send(tcp_socket, msg, strlen(msg), 0);
    recv(tcp_socket, msg, PACK_SIZE, 0);
    printf("server: %s",msg+4);
    return 0;
}

int main(int argc,char *argv[]){
    struct sockaddr_in server;
	int tcp_socket;

    tcp_socket = socket(AF_INET,SOCK_STREAM,0);       //---------|---> open principal socket
                                                      //         |
	if(tcp_socket == -1){                             //         |
		printf("Error: No se pudo crear el socket."); //         |
		return -1;                                    //         |
	}                                                 //---------|

    int size_client = sizeof(server);                 //---------|---> server info
    server.sin_family = AF_INET;                      //         |
	server.sin_port = htons(SERVER_PORT);             //         |
    server.sin_addr.s_addr = inet_addr(SERVER_IP);    //---------|

    if(connect(tcp_socket,(struct sockaddr*) &server,sizeof(server))==-1){
        printf("Error al conectarse con el servidor");
        return -1;
    }

    printf("\nConnection success\n");

    recv(tcp_socket, msg, PACK_SIZE, 0);
    char service_ok[] = {0x32,0x32,0x30};
    if(memcmp(msg,service_ok,3)!=0) {
        printf("Error: service is not ready\n");
        return -1;
    }
    printf("\nServer is ready\n\n");

    if(loggin(tcp_socket)==-1) {
        close(tcp_socket);
        return -1;
    }

    char option[5];
    int  op;

    while(op!=6) {

        printf("\n----------------------\n"
               " 1)pwd\n"
               " 2)ls\n"
               " 3)cd\n"
               " 4)get\n"
               " 5)put\n"
               " 6)quit\n"
               "----------------------\n"
               "\n>> ");

        fgets(option,5,stdin);
        op = atoi(option);
        printf("\n");
        switch (op) {
            case 1: pwd(tcp_socket);  break;
            case 2: ls(tcp_socket);   break;
            case 3: cd(tcp_socket);   break;
            case 4: get(tcp_socket);  break;
            case 5: put(tcp_socket);  break;
            case 6: quit(tcp_socket); break;
        }
    }

    close(tcp_socket);
	return 0;
}
