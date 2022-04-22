#ifndef FUN_H
#define FUN_H

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <sys/time.h>
#include <pthread.h>

struct arg_enviarICMP{
    char*mensaje;
    int num_mensajes;
    int indice;
    int packet_socket;
    struct info_eco * info;
    unsigned int identificador;
};

struct arg_recibirICMP{
    char*mensaje;
    int num_mensajes;
    int packet_socket;
    struct info_eco * info;
    unsigned int identificador;
};

struct info_eco{
    int received;
    unsigned int num_sec;
    struct timeval start;
};

void mostrar_dir(unsigned char*dir, int len);
void mostrar_ip(unsigned char*ip);
int  obtenerDatos(int ds, char*nombre);
void estructuraTrama(unsigned char *trama);
void enviarTrama(int ds, int index, unsigned char* trama, int size);
void imprimirTrama(unsigned char*paq, int len);
void recibirTrama(int ds, unsigned char *trama);
void recibirICMP(int ds, unsigned char *trama, int bytes);
void get_remote_ip(char*ip);
void title(char*msg);
void decabin(int n, int*array) ;
void get_red(unsigned char*ip_origen, unsigned char*ip_mask, unsigned char*red);
int  reduce(unsigned char sum_hex[10]);
void checksum(unsigned char*data, int len, unsigned char*space);
void estructuraDatagramaIP(unsigned char*trama, unsigned int identificador, unsigned int num_sec, char*mensaje, int size);
long get_range_of_time(struct timeval start, struct timeval end);
int  exist_sec(struct arg_recibirICMP* data, unsigned char num_1, unsigned char num_2);
int  get_index_sec(struct arg_recibirICMP* data, unsigned char num_1, unsigned char num_2);

#endif
