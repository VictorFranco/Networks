#include "fun.h"

int exist_sec(struct arg_recibirICMP* data,unsigned char num_1,unsigned char num_2) {
    int i,num_sec = ((num_1<<8)&0xFF00)|(num_2&0x00FF);
    for(i=0; i<data->num_mensajes; i++)
        if(num_sec==data->info[i].num_sec) return 1;
    return 0;
}

int get_index_sec(struct arg_recibirICMP* data,unsigned char num_1,unsigned char num_2) {
    int i,num_sec=((num_1<<8)&0xFF00)|(num_2&0x00FF);
    for(i=0; i<data->num_mensajes; i++)
        if(num_sec==data->info[i].num_sec) return i;
    return -1;
}

long get_range_of_time(struct timeval start,struct timeval end) {
    long seconds, useconds;
    seconds  = end.tv_sec  - start.tv_sec;
    useconds = end.tv_usec - start.tv_usec;
    return ((seconds) * 1000 + useconds/1000.0) + 0.5;
}

int mismo_id(unsigned int identificador,unsigned char num_1,unsigned char num_2) {
    int id=((num_1<<8)&0xFF00)|(num_2&0x00FF);
    return identificador==id;
}

void decabin(int n,int*array) {
    if (n) {
        *array=n%2;
        decabin(n/2,array-1);
    }
}

void get_red(unsigned char*ip_origen,unsigned char*ip_mask,unsigned char*red) {
    int i,j=0;
    for(i=0; i<4; i++) {
        j=ip_origen[i]&ip_mask[i];
        red[i]=j;
    }
}

int reduce(unsigned char sum_hex[10]) {
    char aux[4];
    char final[4];
    memcpy(aux,sum_hex,strlen((char*)sum_hex)-4);
    strcpy(final,(char*)sum_hex+strlen((char*)sum_hex)-4);
    unsigned int complemento  = strtol(aux,NULL,16);
    unsigned int numero_con_4 = strtol(final,NULL,16);
    unsigned int result = complemento+numero_con_4;
    return result;
}

void checksum(unsigned char*data,int len,unsigned char*space) {
    int i;
    unsigned int array[len/2];
    for(i=0; i<len; i+=2) {
        array[i/2]=data[i]*256;
    }
    for(i=1; i<len; i+=2) {
        array[i/2]+=data[i];
    }
    int sum=0;
    for(i=0; i<len/2; i++) sum+=array[i];
    char sum_hex[10];
    sprintf(sum_hex,"%x",sum);
    sum = strlen(sum_hex)>4 ? reduce((unsigned char*)sum_hex) : sum;
    sprintf(sum_hex,"%x",sum);
    sum = strlen(sum_hex)>4 ? reduce((unsigned char*)sum_hex) : sum;
    space[0]=0xFF-(sum>>8)&0x00FF;     //segundo octeto xx:
    space[1]=0xFF-sum&0x00FF;          //primer octeto    :xx
}
