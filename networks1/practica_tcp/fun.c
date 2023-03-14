#include "fun.h"

unsigned char ip_remota[4],ip_origen[4],cadena_ip_remota[20];
unsigned char MACorigen[6],MACremota[7];
unsigned char tramaEnv[1514],tramaRec[1514],datagramaIP[1514];
unsigned char mascara[4];
unsigned char MACbroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2]={0x08,0x06};
unsigned char type_hardware[2]={0x00,0x01};
unsigned char type_protocol[2]={0x08,0x00};
unsigned char long_dir_hardware[2]={0x06,0x00};
unsigned char long_dir_protocolo[2]={0x04,0x00};
unsigned char req_code[2]={0x00,0x01};
unsigned char res_code[2]={0x00,0x02};
unsigned char dir_hard_dest[6]={0x00,0x00,0x00,0x00,0x00,0x00};
long tiempo_respuestas[50];

pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;

int stop_thread=0;

struct timeval start, end, inicio;
long mtime, tiempo_;

extern FILE *output;

void mostrar_dir(unsigned char*dir,int len){
    int i;
    for(i=0;i<len;i++)
        fprintf(output,"%.2x%s",dir[i],i==len-1?"":":");
    fprintf(output,"\n");
}

void mostrar_ip(unsigned char*ip){
    int i;
    for(i=0;i<4;i++) fprintf(output,"%d%s",ip[i],i==3?"":".");
}

int obtenerDatos(int ds,char*nombre){
    int i,index;
    struct ifreq nic;
    strcpy(nic.ifr_name,nombre);
    if(ioctl(ds,SIOCGIFINDEX,&nic)==-1){
        fprintf(output,"\nError al obtener el index");
        exit(0);
    }
    else{
        index=nic.ifr_ifindex;
        fprintf(output,"\n%-13s |---> %d\n","El indice es",nic.ifr_ifindex);

        if(ioctl(ds,SIOCGIFHWADDR,&nic)==-1){
            fprintf(output,"\nError al obtener la MAC");
            exit(0);
        }
        else{
            memcpy(MACorigen,nic.ifr_hwaddr.sa_data,6);
            fprintf(output,"\n%-13s |---> ","La MAC es");
            mostrar_dir(MACorigen,6);
        }
    }

    if(ioctl(ds,SIOCGIFNETMASK,&nic)==-1){
        fprintf(output,"\nError al obtener la mascara");
        exit(0);
    }
    else{
        memcpy(mascara,nic.ifr_netmask.sa_data+2,4);
        fprintf(output,"\n%-13s |---> ","La macara es");
        mostrar_dir(mascara,4);
    }

    if(ioctl(ds,SIOCGIFADDR,&nic)==-1){
        fprintf(output,"\nError al obtener la ip");
        exit(0);
    }
    else{
        memcpy(ip_origen,nic.ifr_addr.sa_data+2,4);
        fprintf(output,"\n%-13s |---> ","La ip origen");
        mostrar_ip(ip_origen);
        fprintf(output," | ");
        mostrar_dir(ip_origen,4);
        fprintf(output,"\n");
    }
    return index;
}

void estructuraTrama(unsigned char *trama){

    memcpy(trama+0,MACbroad,6);            //MAC broadcast
    memcpy(trama+6,MACorigen,6);           //MAC origen
    memcpy(trama+12,ethertype,2);          //ethertype=0806
    memcpy(trama+14,type_hardware,2);      //ethernet
    memcpy(trama+16,type_protocol,2);      //ip
    memcpy(trama+18,long_dir_hardware,2);  //06     Aqui sobre escribo numeros
    memcpy(trama+19,long_dir_protocolo,2); //04
    memcpy(trama+20,req_code,2);           //0001
    memcpy(trama+22,MACorigen,6);          //SHA    origen
    memcpy(trama+28,ip_origen,4);          //SPA
    memcpy(trama+32,dir_hard_dest,6);      //THA    destino
    memcpy(trama+38,ip_remota,4);          //TPA

}

void enviarTrama(int ds,int index,unsigned char* trama,int size){
    int tam;
    struct sockaddr_ll interfaz;
    memset(&interfaz,0x00,sizeof(interfaz));
    interfaz.sll_family=AF_PACKET;
    interfaz.sll_protocol=htons(ETH_P_ALL);
    interfaz.sll_ifindex=index;
    tam=sendto(ds,trama,size,0,(struct sockaddr*)&interfaz,sizeof(interfaz));
    if(tam<-1){
        fprintf(output,"\nError al enviar");
        exit(0);
    }
    else fprintf(output,"\nExito al enviar");
}

void imprimirTrama(unsigned char*paq,int len){
    int i;
    for(i=0;i<len;i++){
        if(i%16==0)
            fprintf(output,"\n");
        fprintf(output,"%.2x ",paq[i]);
    }
    fprintf(output,"\n");
}

void recibirTrama(int ds,unsigned char *trama){
    int tam;
    while(1){
        tam=recvfrom(ds,trama,1514,0,NULL,0);
        if(tam==-1){
            fprintf(output,"\nError al recibir");
            exit(0);
        }
        else {
            if(!memcmp(trama+0,MACorigen,6)&&!memcmp(trama+12,ethertype,2)&&!memcmp(trama+20,res_code,2)&&!memcmp(trama+28,ip_remota,4)){
                int i;
                imprimirTrama(trama,tam);
                fprintf(output,"\nExito al recibir");
                memcpy(MACremota,trama+6,6);
                fprintf(output,"\n");
                break;
            }
        }
    }
}

void get_remote_ip(char*ip){
    char ip_array[4][10];
    strcpy((char*)cadena_ip_remota,ip);
    char* token = strtok(ip, ".");
    int i=0;
    while (token != NULL) {
        strcpy(ip_array[i],token);
        token = strtok(NULL, ".");
        ip_remota[i]=atoi(ip_array[i]);
        i++;
    }
}

void title(char*msg){
    int i;
    for(i=0;i<47;i++) fprintf(output,"-");
    fprintf(output,"\n%s\n",msg);
    for(i=0;i<47;i++) fprintf(output,"-");
}

void decabin (int n,int*array){
    if (n) {
        *array=n%2;
        decabin(n/2,array-1);
    }
}

void get_red(unsigned char*ip_origen,unsigned char*ip_mask,unsigned char*red){
    int i,j=0;
    for(i=0;i<4;i++){
        j=ip_origen[i]&ip_mask[i];
        red[i]=j;
    }
}

int reduce(char sum_hex[10]){
    char aux[4];
    char final[4];
    memcpy(aux,sum_hex,strlen((char*)sum_hex)-4);
    strcpy(final,(char*)sum_hex+strlen((char*)sum_hex)-4);
    unsigned int complemento=strtol(aux,NULL,16);
    unsigned int numero_con_4=strtol(final,NULL,16);
    unsigned int result=complemento+numero_con_4;
    return result;
}

void checksum(unsigned char*data,int len,unsigned char*space){
    int i,j=0;
    unsigned int array[len/2];
    for(i=0;i<len;i+=2){
        array[j]=data[i]*256;
        j++;
    }
    j=0;
    for(i=1;i<len;i+=2){
        array[j]+=data[i];
        j++;
    }
    int sum=0;
    for(i=0;i<len/2;i++){
        sum+=array[i];
    }
    char sum_hex[10];
    sprintf(sum_hex,"%x",sum);
    if(strlen(sum_hex)>4)
        sum=reduce(sum_hex);
    sprintf(sum_hex,"%x",sum);
    if(strlen(sum_hex)>4)
        sum=reduce(sum_hex);
    sprintf(sum_hex,"%x",sum);
    if(strlen(sum_hex)>4)
        sum=reduce(sum_hex);
    sprintf(sum_hex,"%x",sum);
    if(strlen(sum_hex)>4)
        sum=reduce(sum_hex);
    space[0]=0xFF-(sum>>8)&0x00FF;     //segundo octeto xx:
    space[1]=0xFF-(sum&0x00FF);        //primer octeto    :xx
}

void estructuraSegmentoTCP(unsigned char*trama,unsigned int identificador,unsigned int port){
    //Encabezado MAC
    memcpy(trama+0,MACremota,6);
    memcpy(trama+6,MACorigen,6);
    //Encabezado IP
    memcpy(trama+26,ip_origen,4);
    memcpy(trama+30,ip_remota,4);
    trama[18]=(identificador>>8)&0x00FF;
    trama[19]=identificador&0x00FF;
    trama[36]=(port>>8)&0x00FF;
    trama[37]=port&0x00FF;
    unsigned char encabezado_ip[23],calculo_tcp[50],space[2];
    memcpy(encabezado_ip+0,trama+14,20);
    checksum(encabezado_ip,20,space);
    memcpy(trama+24,space,2);
    memcpy(calculo_tcp+0,trama+34,28);
    memcpy(calculo_tcp+28,ip_origen,4);
    memcpy(calculo_tcp+32,ip_remota,4);
    calculo_tcp[36]=0x00;
    calculo_tcp[37]=trama[23];
    calculo_tcp[38]=0x00;
    calculo_tcp[39]=(trama[46]>>4)*4;
    checksum(calculo_tcp,40,space);
    memcpy(trama+50,space,2);
}

void buscar_tipo_puerto(unsigned int port,char info[70]){
    extern char TCP_puertos_conocidos[9][2][70];
    int i,j=0;
    char aux[10];
    sprintf(aux,"%d",port);
    for(i=0;i<9;i++)
        if(strcmp(aux,TCP_puertos_conocidos[i][0])==0)
            strcpy(info,TCP_puertos_conocidos[i][1]);
}

void *proceso_envio_TCP(void *arg){
    struct arg_enviarTCP *data=(struct arg_enviarTCP*)arg;
    int indice=data->indice;
    int packet_socket=data->packet_socket;
    int i,num_sec,identificador;
    for(i=data->inicio;i<data->num_mensajes+1;i++){
        unsigned char segmentoTCP[]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x00,0x45,0x00,0x00,0x30,0x00,0x01,0x00,0x00,0x40,0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0a,0xcc,0x00,0x50,0x0a,0x0b,0x0c,0x0d,0x00,0x00,0x00,0x00,0x70,0x02,0x80,0x00,0x00,0x00,0x00,0x00,0x02,0x04,0x05,0xb4,0x01,0x01,0x04,0x02};
        struct timeval start;
        gettimeofday(&start, NULL);
        title("-> Envio de establecimiento de conexion");
        estructuraSegmentoTCP(segmentoTCP,i*256,i);
        imprimirTrama(segmentoTCP,62);
        enviarTrama(packet_socket,indice,segmentoTCP,62);
        fprintf(output,"\n");
        usleep(0.2*1000000);
    }
    usleep(1000000);
    pthread_mutex_lock(&mutex);//--------|
    stop_thread=1;//                     |zona critica
    pthread_mutex_unlock(&mutex);//------|
    return NULL;
}

long get_range_of_time(struct timeval start,struct timeval end){
    long seconds, useconds;
    seconds  = end.tv_sec  - start.tv_sec;
    useconds = end.tv_usec - start.tv_usec;
    return ((seconds) * 1000 + useconds/1000.0) + 0.5;
}

void *proceso_recibir_TCP(void *arg){
    struct arg_recibirTCP *data=(struct arg_recibirTCP*)arg;
    int ds=data->packet_socket;
    unsigned char*trama=tramaRec;
    int tam;
    int i,index_sec;
    mtime=0;
    unsigned char ethertype[]={0x08,0x00};
    unsigned char protocolo=0x06,respuestaEco=0x00;
    gettimeofday(&start, NULL);
    while(mtime<1000*data->num_mensajes+1){
        tam=recvfrom(ds,trama,1514,MSG_DONTWAIT,NULL,0);
        gettimeofday(&end, NULL);
        mtime = get_range_of_time(start,end);
        if(tam!=-1){
            if(trama[47]==0x12&&trama[23]==protocolo&&!memcmp(trama+0,MACorigen,6)&&!memcmp(trama+12,ethertype,2)&&!memcmp(trama+26,ip_remota,4)){
                fprintf(output,"\n");
                title("-> Respuesta TCP");
                imprimirTrama(trama,tam);
                unsigned int port=((trama[34]<<8)&0xFF00)|(trama[35]&0x00FF);
                char tipo_puerto[70];
                buscar_tipo_puerto(port,tipo_puerto);
                printf("El puerto: %d esta abierto | %s\n",port,tipo_puerto);
                fprintf(output,"\n");
            }
            pthread_mutex_lock(&mutex);//--------|
            if(stop_thread) break;//             |zona critica
            pthread_mutex_unlock(&mutex);//------|
        }
    }
    if(mtime>=1000*data->num_mensajes) printf("Se supero el tiempo de espera\n\n");
    return NULL;
}
