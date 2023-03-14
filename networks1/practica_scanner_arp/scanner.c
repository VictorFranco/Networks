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

unsigned char MACorigen[6];
unsigned char mascara[4];
unsigned char ip_origen[4];
unsigned char MACbroad[6]={0xff,0xff,0xff,0xff,0xff,0xff};
unsigned char ethertype[2]={0x08,0x06};
unsigned char type_hardware[2]={0x00,0x01};
unsigned char type_protocol[2]={0x08,0x00};
unsigned char long_dir_hardware[2]={0x06,0x00};
unsigned char long_dir_protocolo[2]={0x04,0x00};
unsigned char req_code[2]={0x00,0x01};
unsigned char res_code[2]={0x00,0x02};
unsigned char dir_hard_dest[6]={0x00,0x00,0x00,0x00,0x00,0x00};
unsigned char ip_remota[4];
unsigned char cadena_ip_remota[20];
unsigned char tramaEnv[1514],tramaRec[1514];

struct timeval start, end;
long mtime, seconds, useconds;

struct Nodo{
    unsigned char ip[4];
    unsigned char mac[6];
    struct Nodo* siguiente;
};

struct Pila{
    struct Nodo* raiz;
    int tam;
};

struct Pila* crear_pila(){
    struct Pila* pila=(struct Pila*)malloc(sizeof(struct Pila));
    pila->raiz=NULL;
    pila->tam=0;
    return pila;
}

struct Nodo* crear_nodo(){
    struct Nodo* nodo=(struct Nodo*)malloc(sizeof(struct Nodo));
    strcpy(nodo->ip,"");
    strcpy(nodo->mac,"");
    nodo->siguiente=NULL;
    return nodo;
}

int pila_vacia(struct Pila* pila){
    return pila->tam==0;
}

int push(struct Pila* pila,unsigned char ip[4],unsigned char mac[6]){
    if(pila==NULL) return -1;
    struct Nodo* nodo=crear_nodo();
    strcpy(nodo->ip,ip);
    strcpy(nodo->mac,mac);
    nodo->siguiente=pila->raiz;
    pila->raiz=nodo;
    pila->tam++;
    return 0;
}

int pop(struct Pila* pila,unsigned char ip[4],unsigned char mac[6]){
    if(pila==NULL) return -1;
    if(pila_vacia(pila)) return -2;
    struct Nodo* nodo=pila->raiz;
    strcpy(ip,nodo->ip);
    strcpy(mac,nodo->mac);
    pila->raiz=nodo->siguiente;
    nodo->siguiente=NULL;
    free(nodo);
    return 0;
}

int destruir_pila(struct Pila* pila){
    unsigned char ip[1514], mac[1514];
    while(pila->raiz)
        pop(pila,ip,mac);
    free(pila);
    return 0;
}

char* mostrar_dir_hex(unsigned char*dir,int len){
    char* aux=(char*)malloc(30*sizeof(char));
    memset(aux,0x00,30);
    for(int i=0; i<len; i++)
        sprintf(aux+strlen(aux),"%.2x%s",dir[i],i==len-1?"":":");
    return aux;
}

char* mostrar_ip(unsigned char*ip,int len){
    char* aux=(char*)malloc(30*sizeof(char));
    memset(aux,0x00,30);
    for(int i=0; i<len; i++)
        sprintf(aux+strlen(aux),"%d%s",ip[i],i==len-1?"":".");
    return aux;
}

int obtenerDatos(int ds){
    char nombre[20];
    int i,index;
    struct ifreq nic;
    printf("\nInserta el nombre de la interfaz: ");
    fgets(nombre,20,stdin);
    nombre[strlen(nombre)-1] = '\0';
    strcpy(nic.ifr_name,nombre);
    if(ioctl(ds,SIOCGIFINDEX,&nic)==-1){
        perror("\nError al obtener el index");
        exit(0);
    }
    else{
        index=nic.ifr_ifindex;
        printf("\n%-13s |---> %d\n","El indice es",nic.ifr_ifindex);

        if(ioctl(ds,SIOCGIFHWADDR,&nic)==-1){
            perror("\nError al obtener la MAC");
            exit(0);
        }
        else{
            memcpy(MACorigen,nic.ifr_hwaddr.sa_data,6);
            printf("\n%-13s |---> ","La MAC es");
            char*mac_=mostrar_dir_hex(MACorigen,6);
            printf("%s\n",mac_);
            free(mac_);
        }
    }

    if(ioctl(ds,SIOCGIFNETMASK,&nic)==-1){
        perror("\nError al obtener la mascara");
        exit(0);
    }
    else{
        memcpy(mascara,nic.ifr_netmask.sa_data+2,4);
        printf("\n%-13s |---> ","La macara es");
        char*mac_=mostrar_dir_hex(mascara,4);
        printf("%s\n",mac_);
        free(mac_);
    }

    if(ioctl(ds,SIOCGIFADDR,&nic)==-1){
        perror("\nError al obtener la ip");
        exit(0);
    }
    else{
        memcpy(ip_origen,nic.ifr_addr.sa_data+2,4);
        printf("\n%-13s |---> ","La ip es");
        char*ip_=mostrar_ip(ip_origen,4);
        printf("%s",ip_);
        free(ip_);
        printf(" | ");
        char*ip_hex=mostrar_dir_hex(ip_origen,4);
        printf("%s\n",ip_hex);
        printf("\n");
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

void enviarTrama(int ds,int index,unsigned char* trama){
    int tam;
    struct sockaddr_ll interfaz;
    memset(&interfaz,0x00,sizeof(interfaz));
    interfaz.sll_family=AF_PACKET;
    interfaz.sll_protocol=htons(ETH_P_ALL);
    interfaz.sll_ifindex=index;
    tam=sendto(ds,trama,60,0,(struct sockaddr*)&interfaz,sizeof(interfaz));
    if(tam<-1){
        printf("  Error al enviar\n");
        exit(0);
    }
}

void imprimirTrama(unsigned char*paq,int len){
    int i;
    for(i=0;i<len;i++){
        if(i%16==0)
            printf("\n");
        printf("%.2x ",paq[i]);
    }
    printf("\n");
}

void recibirTrama(int ds, unsigned char *trama,struct Pila* pila){
    int tam;
    mtime=0;
    gettimeofday(&start, NULL);
    while(mtime<1000){
        tam=recvfrom(ds,trama,1514,MSG_DONTWAIT,NULL,0);
        gettimeofday(&end, NULL);
        seconds  = end.tv_sec  - start.tv_sec;
        useconds = end.tv_usec - start.tv_usec;
        mtime = ((seconds) * 1000 + useconds/1000.0) + 0.5;
        if(tam!=-1){
            if(!memcmp(trama+0,MACorigen,6)&&!memcmp(trama+12,ethertype,2)&&!memcmp(trama+20,res_code,2)&&!memcmp(trama+28,ip_remota,4)){
                unsigned char mac_remota[7];
                memcpy(mac_remota,trama+6,6);
                printf(" => Respondio en %ld milisegundos\n", mtime);
                push(pila,ip_remota,mac_remota);
                break;
            }
        }
    }
    if(mtime>=500) printf(" => Sin respuesta\n");
}

void get_remote_ip(){
    char ip[100];
    char ip_array[4][10];
    strcpy(ip,"");
    printf("\nInserta la ip remota: ");
    fgets(ip,100,stdin);
    strcpy(cadena_ip_remota,ip);
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
    for(i=0;i<47;i++) printf("-");
    printf("\n%s\n",msg);
    for(i=0;i<47;i++) printf("-");
    printf("\n");
}

int main(){
    int packet_socket,indice,i,j;
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(packet_socket==-1){
        perror("\nError al abrir el socket");
        exit(0);
    }
    else{
        perror("\nExito al abrir el socket");
        //get_remote_ip();
        indice=obtenerDatos(packet_socket);
        struct Pila* pila=crear_pila();
        for(i=1;i<255;i++){
            memcpy(ip_remota,ip_origen,4);
            ip_remota[3]=i;
            char*ip_=mostrar_ip(ip_remota,4);
            printf("%-13s",ip_);
            free(ip_);
            estructuraTrama(tramaEnv);
            enviarTrama(packet_socket,indice,tramaEnv);
            recibirTrama(packet_socket,tramaRec,pila);
        }
        remove("output.txt");//Eliminamos el archivo

        FILE*archivo=fopen("output.txt","w");
        if(archivo==NULL) printf("=========> El archivo no se pudo abrir\n");

        printf("\n");
        title("Resultados del scanner en output.txt");
        printf("\n");
        for(i=0;i<pila->tam;i++){
            unsigned char ip[4],mac[6];
            pop(pila,ip,mac);
            char*ip_=mostrar_ip(ip,4);
            fprintf(archivo,"%-13s",ip_);
            free(ip_);
            fprintf(archivo," <==> ");
            char*mac_=mostrar_dir_hex(mac,6);
            fprintf(archivo,"%s\n\n",mac_);
            free(mac_);
        }
        fclose(archivo);
        destruir_pila(pila);
    }
    close(packet_socket);
    return 0;
}
