#include <asm-generic/socket.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sendfile.h>
#include <fcntl.h>

#define TCP_PORT     80
#define BUFFER_REQ   512
#define BUFFER_PAGE  3000
#define BUFFER_IMG   100000
#define HEAD_HTML    "HTTP/1.1 200 OK\r\nContent-Type: text/html;charset=UTF-8\r\n\r\n"
#define HEAD_IMAGE   "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n"

/************************/
// Author: Victor Franco
// Date:   04/23/2022
/************************/

void showBytes(unsigned char*block,int len) {
    for (int i=0; i<len; i++) {
        if(i%16 == 0) printf("\n");
        if(i%8 == 0)  printf("    ");
        printf("0x%02x ", block[i]);
    }
}

void createMessage(unsigned char*message,char*nameOfFile) {
    strcpy((char*)message,HEAD_HTML);               // add header to message
    FILE*file = fopen(nameOfFile,"r");
    unsigned char page[BUFFER_PAGE];
    unsigned char*pointer = page;
    char aux;
    char check = 0;
    while((aux = fgetc(file)) != EOF) {             // while the character is not the end
        !check && (check = aux != ' ' ? 1 : 0);     // skip the enter(0x0a) from file
        check = aux == 0x0a ? 0 : check;
        check && (*pointer++ = aux);                // save the character
    }
    *pointer = '\0';                                // append 0x00
    strcat((char*)message,(char*)page);             // concatenate page to message
    fclose(file);
}

void sendImage(int fd_client,char*nameOfFile,char*type) {
    FILE*image = fopen(nameOfFile,"rb");
    char buffer[BUFFER_IMG];
    int size_file;
    size_file = fread(buffer,1,BUFFER_IMG,image);             // save image bytes in buffer
    char message[BUFFER_IMG];
    sprintf(message,HEAD_IMAGE,type,size_file);               // add header to message
    int size_head = strlen(message);
    memcpy((char*)message+size_head,(char*)buffer,size_file); // concatenate buffer in message
    send(fd_client, message, size_head+size_file, 0);         // send message
}

int main(){
    unsigned char paqRec[BUFFER_REQ], message[BUFFER_PAGE];

	int tcp_socket,lbind;
	struct sockaddr_in server,cliente;
	tcp_socket = socket(AF_INET,SOCK_STREAM,0);
	if(tcp_socket == -1) {
        perror("Error al abrir el socket\n");
		return -1;
	}
    int on = 1;
    setsockopt(tcp_socket,SOL_SOCKET,SO_REUSEADDR,&on,sizeof(int));
	server.sin_family = AF_INET;
	server.sin_port = htons(TCP_PORT);
    server.sin_addr.s_addr = INADDR_ANY;

	lbind = bind(tcp_socket,(struct sockaddr *) &server,sizeof(server));

    if(lbind == -1) {
        perror("\nError en bind");
        close(tcp_socket);
        return -1;
    }

    if(listen(tcp_socket,10)==-1){
        perror("Error al encolar la peticion\n");
        close(tcp_socket);
		return -1;
    }

    for(int i=0; i<40; i++) printf("-");
    printf("\nServidor activo en el puerto => %d\n",TCP_PORT);
    for(int i=0; i<40; i++) printf("-");
    printf("\n");

    socklen_t size_client = sizeof(cliente);

    createMessage(message,"src/index.html"); // generate message with index.html

    int fd_client,image;
    while(1) {
        fd_client = accept(tcp_socket,(struct sockaddr *) &cliente,&size_client);
        if(fd_client==-1) {
            perror("conexion fallida");
            continue;
        }
        if(!fork()) {
            close(tcp_socket);
            recv(fd_client, paqRec, BUFFER_REQ, 0);
            // printf("%s\n",paqRec);
            if(!memcmp(paqRec,"GET /favicon.ico HTTP/1.1",25)) {
                sendImage(fd_client,"src/favicon.ico","image/icon");
                close(image);
            }
            else if(!memcmp(paqRec,"GET /skull.jpg HTTP/1.1",23)) {
                sendImage(fd_client,"src/skull.jpg","image/jpg");
                close(image);
            }
            else send(fd_client, message, strlen((char*)message), 0); // send index.html
            close(fd_client);
            return 0;
        }
        close(fd_client);
    }
	return 0;
}
