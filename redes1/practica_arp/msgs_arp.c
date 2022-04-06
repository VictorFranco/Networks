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

void mostrar_dir(unsigned char*dir,int len){
    int i;
    for(i=0;i<len;i++)
        printf("%.2x%s",dir[i],i==len-1?"":":");
    printf("\n");
}
int obtenerDatos(int ds){
    unsigned char nombre[20];
    int i,index;
    struct ifreq nic;
    printf("\nInserta el nombre de la interfaz: ");
    gets(nombre);
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
            mostrar_dir(MACorigen,6);
        }
    }

    if(ioctl(ds,SIOCGIFNETMASK,&nic)==-1){
        perror("\nError al obtener la mascara");
        exit(0);
    }
    else{
        memcpy(mascara,nic.ifr_netmask.sa_data+2,4);
        printf("\n%-13s |---> ","La macara es");
        mostrar_dir(mascara,4);
    }

    if(ioctl(ds,SIOCGIFADDR,&nic)==-1){
        perror("\nError al obtener la ip");
        exit(0);
    }
    else{
        memcpy(ip_origen,nic.ifr_addr.sa_data+2,4);
        printf("\n%-13s |---> ","La ip origen");
        for(i=0;i<4;i++) printf("%d%s",ip_origen[i],i==3?"":".");
        printf(" | ");
        mostrar_dir(ip_origen,4);
        printf("\n");

        printf("%-13s |---> ","La ip remota");
        printf("%s",cadena_ip_remota);
        printf(" | ");
        mostrar_dir(ip_remota,4);
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
        perror("\nError al enviar");
        exit(0);
    }
    else perror("\nExito al enviar");
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
void recibirTrama(int ds, unsigned char *trama){
    int tam;
    while(1){
        tam=recvfrom(ds,trama,1514,0,NULL,0);
        if(tam==-1){
            perror("\nError al recibir");
            exit(0);
        }
        else {
            if(!memcmp(trama+0,MACorigen,6)&&!memcmp(trama+12,ethertype,2)&&!memcmp(trama+20,res_code,2)&&!memcmp(trama+28,ip_remota,4)){
                imprimirTrama(trama,tam);
                //imprimirTrama(trama,42);
                perror("\nExito al recibir");
                unsigned char mac_remota[7];
                memcpy(mac_remota,trama+6,6);
                printf("\n");
                int i;
                for(i=0;i<47;i++) printf("-");
                printf("\n--> La mac de %s es ",cadena_ip_remota);
                mostrar_dir(mac_remota,6);
                for(i=0;i<47;i++) printf("-");
                break;
            }
        }
    }
}
void get_remote_ip(){
    char ip[100];
    char ip_array[4][10];
    strcpy(ip,"");
    printf("\nInserta la ip remota: ");
    gets(ip);
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
    int packet_socket,indice;
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(packet_socket==-1){
        perror("\nError al abrir el socket");
        exit(0);
    }
    else{
        perror("\nExito al abrir el socket");
        get_remote_ip();
        indice=obtenerDatos(packet_socket);
        estructuraTrama(tramaEnv);
        printf("\n");
        title("-> Solicitud ARP");
        imprimirTrama(tramaEnv,42);
        enviarTrama(packet_socket,indice,tramaEnv);
        printf("\n");
        title("-> Respuesta ARP");
        recibirTrama(packet_socket,tramaRec);
        printf("\n");
    }
    close(packet_socket);
    return 0;
}
