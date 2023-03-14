#ifndef FUN_H
#define FUN_H

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>

struct arg_enviarTCP{
    int inicio;
    int num_mensajes;
    int indice;
    int packet_socket;
    unsigned int identificador;
};

struct arg_recibirTCP{
    int num_mensajes;
    int packet_socket;
    unsigned int identificador;
};

void mostrar_dir(unsigned char*dir,int len);
void mostrar_ip(unsigned char*ip);
int  obtenerDatos(int ds,char*nombre);
void estructuraTrama(unsigned char *trama);
void enviarTrama(int ds,int index,unsigned char* trama,int size);
void imprimirTrama(unsigned char*paq,int len);
void recibirTrama(int ds,unsigned char *trama);
void recibirICMP(int ds,unsigned char *trama,int bytes);
void get_remote_ip(char*ip);
void title(char*msg);
void decabin (int n,int*array) ;
void get_red(unsigned char*ip_origen,unsigned char*ip_mask,unsigned char*red);
int  reduce(char sum_hex[10]);
void checksum(unsigned char*data,int len,unsigned char*space);
void estructuraSegmentoTCP(unsigned char* trama,unsigned int identificador,unsigned int port);
void *proceso_envio_TCP(void *arg);
void *proceso_recibir_TCP(void *arg);

#endif
