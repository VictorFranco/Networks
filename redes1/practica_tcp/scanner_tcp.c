#include "fun.h"

char TCP_puertos_conocidos[9][2][70]={
{"19","(NNTP) Protocolo de Transferencia de noticias de la red"},
{"20","(Servidor FTP) canal de datos - puede ser aleatorio"},
{"21","(Servidor FTP) canal de control"},
{"23","Servidor Telnet"},
{"25","(SMTP) Protocolo simple de transferencia de correo"},
{"80","(HTTP; servidor WEB) Protocolo de Transferencia de Hipertexto"},
{"139","Servidor de sesion de NetBIOS"},
{"339","(LDAP) Protocolo ligero de acceso a directorios"},
{"445","(SMB, Server Message Block) Bloque de mensajes de servidor"}};

FILE*output;

int main(int argc,char *argv[]){
    extern unsigned char ip_remota[4],ip_origen[4],cadena_ip_remota[20];
    extern unsigned char tramaEnv[1514],tramaRec[1514],MACremota[7],mascara[4];

    printf("\n");
    int packet_socket,indice;
    output=fopen("output.txt","w");
    pthread_t hilo_enviar,hilo_escuchar;
    packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(packet_socket==-1){
        fprintf(output,"Error al abrir el socket\n");
        exit(0);
    }
    else{
        fprintf(output,"Exito al abrir el socket\n");
        get_remote_ip(argv[1]);
        indice=obtenerDatos(packet_socket,argv[2]);
        fprintf(output,"%-13s |---> ","La ip remota");
        fprintf(output,"%s",cadena_ip_remota);
        fprintf(output," | ");
        mostrar_dir(ip_remota,4);
        fprintf(output,"\n");
        int i;
        for(i=0;i<47;i++) fprintf(output,"=");
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
        if(!memcmp(red_origen,red_remota,4)){
            title("---> Estan en la misma red");
        }
        else{
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
        for(i=0;i<47;i++) fprintf(output,"-");
        fprintf(output,"\n--> La mac para %s es ",cadena_ip_remota);
        mostrar_dir(MACremota,6);
        for(i=0;i<47;i++) fprintf(output,"-");
        fprintf(output,"\n");
        if(memcmp(red_origen,red_remota,4))
            memcpy(ip_remota,ip_remota_afuera,4);

        int inicio=0;
        int enviar=100;
        if(argc>=4) inicio=atoi(argv[3]);
        if(argc>=5) enviar=atoi(argv[4]);

        struct arg_enviarTCP arg1;
        arg1.packet_socket=packet_socket;
        arg1.inicio=inicio;
        arg1.num_mensajes=enviar;
        arg1.indice=indice;

        struct arg_recibirTCP arg2;
        arg2.packet_socket=packet_socket;
        arg2.num_mensajes=enviar;

        pthread_create(&hilo_enviar,NULL,proceso_envio_TCP,(void*)&arg1);//------|
        pthread_create(&hilo_escuchar,NULL,proceso_recibir_TCP,(void*)&arg2);//  |Threads
        pthread_join(hilo_enviar,NULL);//                                        |
        pthread_join(hilo_escuchar,NULL);//--------------------------------------|
    }
    printf("\n");
    close(packet_socket);
    fclose(output);
    return 0;
}
