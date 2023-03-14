#include "fun.h"

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

unsigned char MACorigen[6];
unsigned char mascara[4];
unsigned char ip_origen[4];
unsigned char ip_remota[4];
unsigned char tramaEnv[1514],tramaRec[1514],datagramaIP[1514];
unsigned char MACremota[7];
unsigned char cadena_ip_remota[20];

unsigned char MACbroad[6]  = {0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2] = {0x08,0x06};
unsigned char type_hardware[2] = {0x00,0x01};
unsigned char type_protocol[2] = {0x08,0x00};
unsigned char long_dir_hardware[2]  = {0x06,0x00};
unsigned char long_dir_protocolo[2] = {0x04,0x00};
unsigned char req_code[2] = {0x00,0x01};
unsigned char res_code[2] = {0x00,0x02};
unsigned char dir_hard_dest[6] = {0x00,0x00,0x00,0x00,0x00,0x00};

long tiempo_respuestas[50];
int index_array;
FILE *output;

struct timeval start, end, inicio;
long mtime, tiempo_;

void mostrar_dir(unsigned char*dir,int len) {
    int i;
    for(i=0; i<len; i++)
        fprintf(output,"%.2x%s",dir[i],i==len-1?"":":");
    fprintf(output,"\n");
}

void mostrar_ip(unsigned char*ip) {
    int i;
    for(i=0; i<4; i++) fprintf(output,"%d%s",ip[i],i==3?"":".");
}

int obtenerDatos(int ds,char*nombre) {
    int i,index;
    struct ifreq nic;
    strcpy(nic.ifr_name,nombre);
    if(ioctl(ds,SIOCGIFINDEX,&nic)==-1) {
        fprintf(output,"\nError al obtener el index");
        exit(0);
    }
    else {
        index=nic.ifr_ifindex;
        fprintf(output,"\n%-13s |---> %d\n","El indice es",nic.ifr_ifindex);

        if(ioctl(ds,SIOCGIFHWADDR,&nic)==-1) {
            fprintf(output,"\nError al obtener la MAC");
            exit(0);
        }
        else {
            memcpy(MACorigen,nic.ifr_hwaddr.sa_data,6);
            fprintf(output,"\n%-13s |---> ","La MAC es");
            mostrar_dir(MACorigen,6);
        }
    }

    if(ioctl(ds,SIOCGIFNETMASK,&nic)==-1) {
        fprintf(output,"\nError al obtener la mascara");
        exit(0);
    }
    else {
        memcpy(mascara,nic.ifr_netmask.sa_data+2,4);
        fprintf(output,"\n%-13s |---> ","La macara es");
        mostrar_dir(mascara,4);
    }

    if(ioctl(ds,SIOCGIFADDR,&nic)==-1) {
        fprintf(output,"\nError al obtener la ip");
        exit(0);
    }
    else {
        memcpy(ip_origen,nic.ifr_addr.sa_data+2,4);
        fprintf(output,"\n%-13s |---> ","La ip origen");
        mostrar_ip(ip_origen);
        fprintf(output," | ");
        mostrar_dir(ip_origen,4);
        fprintf(output,"\n");
    }
    return index;
}

void estructuraTrama(unsigned char *trama) {

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

void enviarTrama(int ds,int index,unsigned char* trama,int size) {
    int tam;
    struct sockaddr_ll interfaz;
    memset(&interfaz,0x00,sizeof(interfaz));
    interfaz.sll_family=AF_PACKET;
    interfaz.sll_protocol=htons(ETH_P_ALL);
    interfaz.sll_ifindex=index;
    tam=sendto(ds,trama,size,0,(struct sockaddr*)&interfaz,sizeof(interfaz));
    if(tam<-1) {
        fprintf(output,"\nError al enviar");
        exit(0);
    }
    else fprintf(output,"\nExito al enviar");
}

void imprimirTrama(unsigned char*paq,int len) {
    int i;
    for(i=0; i<len; i++) {
        if(i%16==0)
            fprintf(output,"\n");
        fprintf(output,"%.2x ",paq[i]);
    }
    fprintf(output,"\n");
}

void recibirTrama(int ds,unsigned char *trama) {
    int tam;
    while(1) {
        tam=recvfrom(ds,trama,1514,0,NULL,0);
        if(tam==-1) {
            fprintf(output,"\nError al recibir");
            exit(0);
        }
        else {
            if(!memcmp(trama+0,MACorigen,6)&&!memcmp(trama+12,ethertype,2)&&!memcmp(trama+20,res_code,2)&&!memcmp(trama+28,ip_remota,4)) {
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

void get_remote_ip(char*ip) {
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

void title(char*msg) {
    int i;
    for(i=0; i<47; i++) fprintf(output,"-");
    fprintf(output,"\n%s\n",msg);
    for(i=0; i<47; i++) fprintf(output,"-");
}

void estructuraDatagramaIP(unsigned char*trama,unsigned int identificador,unsigned int num_sec,char*mensaje,int size) {

    //Encabezado MAC
    memcpy(trama+0,MACremota,6);           //MAC destino
    memcpy(trama+6,MACorigen,6);           //MAC origen
    unsigned char ethertype[2]={0x08,0x00};
    memcpy(trama+12,ethertype,2);          //ethertype=0800
    //Encabezado IP
    trama[14]=0x45;                        //version*IHL=20
    trama[15]=0x00;                        //tipo de servicio
    trama[16]=(size+28)>>8&0x00FF;
    trama[17]=(size+28)&0x00FF;            //long datagrama
    trama[18]=(identificador>>8)&0x00FF;
    trama[19]=identificador&0x00FF;
    unsigned char banderas[]={0x40,0x00};
    memcpy(trama+20,banderas,2);           //banderas
    trama[22]=0x40;                        //tiempo de vida 60s
    trama[23]=0x01;                        //protocolo
    trama[24]=0x00;trama[25]=0x00;         //checksum();
    memcpy(trama+26,ip_origen,4);          //ip origen
    memcpy(trama+30,ip_remota,4);          //ip remota
    //Encabezado ICMP
    trama[34]=0x08;                        //tipo solicitud
    trama[35]=0x00;                        //codigo
    trama[36]=0x00;trama[37]=0x00;         //checksum();
    unsigned char id_[]={0x00,0x05};
    memcpy(trama+38,id_,2);                //identificador
    trama[40]=(num_sec>>8)&0x00FF;
    trama[41]=num_sec&0x00FF;              //num secuencia
    memcpy(trama+42,mensaje,size);

    //checksum encabezado ip
    unsigned char encabezado_ip[23];
    unsigned char space[2];
    memcpy(encabezado_ip+0,trama+14,20);
    checksum(encabezado_ip,20,space);
    memcpy(trama+24,space,2);

    //checksum icmp
    unsigned char icmp[size+8];
    memcpy(icmp+0,trama+34,size+8);
    checksum(icmp,size+8,space);
    memcpy(trama+36,space,2);
}

void *proceso_envio_ICMP(void *arg) {
    struct arg_enviarICMP *data=(struct arg_enviarICMP*)arg;
    char*mensaje=data->mensaje;
    int size=strlen(mensaje);
    int size_trama=42+size;
    int indice=data->indice;
    int i,num_sec,identificador;
    for(i=0; i<data->num_mensajes; i++) {
        struct timeval start;
        gettimeofday(&start, NULL);
        title("-> Solicitud ICMP");
        data->info[i].start=start;
        pthread_mutex_lock(&mutex);//--------|
        data->info[i].received=1;//          |
        num_sec=data->info[i].num_sec;//     |zona critica
        identificador=data->identificador;// |
        pthread_mutex_unlock(&mutex);//------|
        estructuraDatagramaIP(datagramaIP,i,num_sec,mensaje,size);
        imprimirTrama(datagramaIP,size_trama);
        enviarTrama(data->packet_socket,indice,datagramaIP,size_trama);
        fprintf(output,"\n");
        usleep(0.5*1000000);
    }
    return NULL;
}

void *proceso_recibir_ICMP(void *arg) {
    struct arg_recibirICMP *data=(struct arg_recibirICMP*)arg;
    unsigned char*trama=tramaRec;
    int size=strlen(data->mensaje);
    int ds=data->packet_socket;
    int bytes=42+size-34;
    int tam;
    int i,index_sec;
    mtime=0;
    unsigned char ethertype[]={0x08,0x00};
    unsigned char protocolo=0x01,respuestaEco=0x00;
    gettimeofday(&start, NULL);
    while(mtime<1000*data->num_mensajes) {
        tam=recvfrom(ds,trama,1514,MSG_DONTWAIT,NULL,0);
        gettimeofday(&end, NULL);
        mtime = get_range_of_time(start,end);
        if(tam!=-1) {
            if(trama[23]==protocolo&&trama[34]==respuestaEco&&!memcmp(trama+0,MACorigen,6)&&!memcmp(trama+12,ethertype,2)&&!memcmp(trama+26,ip_remota,4)) {
                pthread_mutex_lock(&mutex);//---------------------------|
                if(!exist_sec(data,trama[40],trama[41])) continue;//    |zona critica
                index_sec=get_index_sec(data,trama[40],trama[41]);//    |
                data->info[index_sec].received=2;//                     |
                pthread_mutex_unlock(&mutex);//-------------------------|
                inicio=data->info[index_sec].start;
                tiempo_ = get_range_of_time(inicio,end);
                fprintf(output,"\n");
                title("-> Respuesta ICMP");
                imprimirTrama(trama,tam);
                fprintf(output,"\n");
                printf("Respuesta desde %s:bytes=%d tiempo=%-3ld milisegundos ttl=%d\n\n",cadena_ip_remota,bytes,tiempo_,trama[22]);
                tiempo_respuestas[index_array]=tiempo_;
                index_array++;
            }
        }
        if(index_array==data->num_mensajes) break;
        for(i=0; i<data->num_mensajes; i++) {
            pthread_mutex_lock(&mutex);
            if(data->info[i].received==1) {
                tiempo_ = get_range_of_time(data->info[i].start,end);
                if(tiempo_>=1000) {
                    data->info[i].received=2;
                    printf("=> La red es inalcanzable\n\n");
                }
            }
            pthread_mutex_unlock(&mutex);
        }
    }
    if(mtime>=1000*data->num_mensajes) printf("Se supero el tiempo de espera\n\n");
    return NULL;
}

int main(int argc,char *argv[]) {
    printf("\n");
    index_array=0;
    int packet_socket,indice;
    output=fopen("output.txt","w");
    pthread_t hilo_enviar,hilo_escuchar;
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(packet_socket==-1) {
        fprintf(output,"Error al abrir el socket\n");
        exit(0);
    }
    else {
        fprintf(output,"Exito al abrir el socket\n");
        get_remote_ip(argv[1]);
        indice=obtenerDatos(packet_socket,argv[2]);
        fprintf(output,"%-13s |---> ","La ip remota");
        fprintf(output,"%s",cadena_ip_remota);
        fprintf(output," | ");
        mostrar_dir(ip_remota,4);
        fprintf(output,"\n");
        int i;
        for(i=0; i<47; i++) fprintf(output,"=");
        fprintf(output,"\n");
        unsigned char red_origen[4];
        unsigned char red_remota[4];
        unsigned char ip_remota_afuera[4];
        get_red(ip_origen,mascara,red_origen);
        fprintf(output,"\n%-13s |---> ","Red origen");
        mostrar_dir(red_origen,4);
        get_red(ip_remota,mascara,red_remota);
        fprintf(output,"\n%-13s |---> ","Red remota");
        mostrar_dir(red_remota,4);
        fprintf(output,"\n");
        if(!memcmp(red_origen,red_remota,4)) {
            title("---> Estan en la misma red");
        }
        else {
            title("---> Estan en redes diferentes");
            unsigned char ip_router[]={192,168,1,254};//puerta de enlace
            fprintf(output,"\n");
            mostrar_ip(ip_remota);
            fprintf(output," <==> ");
            mostrar_ip(ip_router);
            fprintf(output," | ");
            mostrar_dir(ip_router,4);
            memcpy(ip_remota_afuera,ip_remota,4);
            memcpy(ip_remota,ip_router,4);
        }
        estructuraTrama(tramaEnv);
        fprintf(output,"\n");
        title("-> Solicitud ARP");//----------------------|
        imprimirTrama(tramaEnv,42);//                     |
        enviarTrama(packet_socket,indice,tramaEnv,42);//  |Envio de ARP
        fprintf(output,"\n");//---------------------------|
        title("-> Respuesta ARP");//----------------------------|
        recibirTrama(packet_socket,tramaRec);//                 |Recibir ARP
        fprintf(output,"\n");//---------------------------------|
        for(i=0; i<47; i++) fprintf(output,"-");
        fprintf(output,"\n--> La mac para %s es ",cadena_ip_remota);
        mostrar_dir(MACremota,6);
        for(i=0; i<47; i++) fprintf(output,"-");
        fprintf(output,"\n");
        if(memcmp(red_origen,red_remota,4))
            memcpy(ip_remota,ip_remota_afuera,4);
        char mensaje[33]="Hello there!\0";
        if(argc>=5) {
            int tam_msg=strlen(argv[4]);
            if(tam_msg%2) strcat(argv[4],"_");
            strcpy(mensaje,argv[4]);
        }
        int enviar=4;
        int identificador=256;
        enviar = argc>=4 ? atoi(argv[3]) : enviar;

        struct info_eco info[enviar];
        for(i=0; i<enviar; i++) {
            info[i].received=0;
            info[i].num_sec=(i+1)*256;
        }

        struct arg_enviarICMP arg1;
        arg1.mensaje = mensaje;
        arg1.packet_socket = packet_socket;
        arg1.num_mensajes  = enviar;
        arg1.indice = indice;
        arg1.info = info;
        arg1.identificador = identificador;

        struct arg_recibirICMP arg2;
        arg2.mensaje = mensaje;
        arg2.packet_socket = packet_socket;
        arg2.num_mensajes  = enviar;
        arg2.info = info;
        arg2.identificador = identificador;

        pthread_create(&hilo_enviar,NULL,proceso_envio_ICMP,(void*)&arg1);//-----|
        pthread_create(&hilo_escuchar,NULL,proceso_recibir_ICMP,(void*)&arg2);// |Threads
        pthread_join(hilo_enviar,NULL);//                                        |
        pthread_join(hilo_escuchar,NULL);//--------------------------------------|

        int perdidos=enviar-index_array;
        printf("Estadisticas de ping para %s:\n\n",cadena_ip_remota);
        printf("    Paquetes: enviados = %d, recibidos = %d, perdidos = %d\n\n",enviar,index_array,perdidos);
        printf("    (%.2f%% perdidos)\n\n",(float)perdidos/enviar*100);
        if(index_array==0) return 0;
        long max=tiempo_respuestas[0],min=max,avg=max;
        long sum=0;
        for(i=0; i<index_array; i++) {
            max = tiempo_respuestas[i]>max ? tiempo_respuestas[i] : max;
            min = tiempo_respuestas[i]<min ? tiempo_respuestas[i] : min;
            sum+=tiempo_respuestas[i];
        }
        printf("Tiempos de ida y vuelta en milisegundos:\n\n");
        printf("    Minimo = %ld milisegundos, Maximo = %ld milisegundos, Media = %ld milisegundos\n\n",min,max,sum/index_array);
    }
    close(packet_socket);
    fclose(output);
    return 0;
}
