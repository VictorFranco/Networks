#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

//prototipos
void mostrar(const char[150][2],const int);
int  dividir(const char*,const int,char[150][2]);
void buscar_protocolo(const char[2],char[60]);
void hextobin(char[]);
void decabin (int,int*);
void analizar(const char[150][2],const int);
void buscar_trama_no_num(int*MM,char[20]);

char protocolos[27][2][60] = {
{"00","Null LSAP "},
{"02","Individual LLC Sublayer Management Function "},
{"03","Group LLC Sublayer Management Function "},
{"04","IBM SNA Path Control (individual) "},
{"05","IBM SNA Path Control (group) "},
{"06","ARPANET Internet Protocol (IP) "},
{"08","SNA "},
{"0c","SNA "},
{"0e","PROWAY (IEC955) Network Management & Initialization"},
{"18","Texas Instruments"},
{"42","IEEE 802.1 Bridge Spanning Tree Protocol "},
{"4e","EIA RS-511 Manufacturing Message Service "},
{"7e","ISO 8208 (X.25 over IEEE 802.2 Type 2 LLC) "},
{"80","Xerox Network Systems (XNS) "},
{"86","Nestar "},
{"8e","PROWAY (IEC 955) Active Station List Maintenance "},
{"98","ARPANET Address Resolution Protocol (ARP) "},
{"bc","Banyan VINES "},
{"aa","SubNetwork Access Protocol (SNAP) "},
{"e0","Novell NetWare "},
{"f0","IBM NetBIOS "},
{"f4","IBM LAN Management (individual) "},
{"f5","IBM LAN Management (group) "},
{"f8","IBM Remote Program Load (RPL) "},
{"fa","Ungermann-Bass "},
{"fe","ISO Network Layer Protocol "},
{"ff","Global LSAP"}};

char tramas_no_num[17][2][60] = {
{"10000","SNRM Set normal response SNRM"},
{"11011","SNRME Set normal response extended mode"},
{"00011","SARM Set asynchronous response"},
{"01011","SARME Set asynchronous extended mode"},
{"00111","SABM Set asynchronous balanced mode"},
{"01111","SABME Set asynchronous balanced extended mode"},
{"00001","SIM Set initialization mode"},
{"01000","DISC Disconnect"},
{"01100","UA Unnumbered Acknowledgment"},
{"00011","DM Disconnect Mode"},
{"01000","RD Request Disconnect"},
{"00001","RIM Request Initialization Mode"},
{"00000","UI Unnumbered Information"},
{"00100","UP Unnumbered Poll"},
{"10011","RSET Exchange Indentification"},
{"10111","XID Exchange Identification"},
{"11100","TEST Test"}};

int main() {
    int i;
    char trama[700];
    FILE*tramas;
    tramas=fopen("tramas.txt","r");
    char transform[300][2];
    for(i=0; i<45; i++) {
        printf("\n--> %d\n-----------------------------------------------\n",i+1);
        strcpy(trama,"");
        fgets(trama,700,tramas);
        int tam=dividir(trama,strlen(trama),transform);
        analizar(transform,tam);
        printf("-----------------------------------------------\n");
    }
    return 0;
}

int dividir(const char*trama,const int size,char transform[300][2]) {
    int tam=(int)size/3+1;
    int i,j;
    for(i=0; i<tam; i++) strcpy(transform[i],"");
    for(i=0; *trama!='\0'; trama++)
        if(*trama!=' ') strncat(transform[i],trama,1);
        else i++;
    mostrar(transform,tam);
    return tam;
}

void mostrar(const char transform[300][2],const int tam) {
    int i,j;
    for(i=0; i<tam; i++) {
        for(j=0; j<2; j++)
            printf("%c",transform[i][j]);
        if(j==2) printf(" ");
        if((i+1)%16==0)
            printf("\n");
    }
    printf("\n");
}

void analizar(const char transform[300][2],const int tam) {
    int i,j;
    int num_control=0;
    for(i=0; i<tam; i++) {
        if(num_control==2) break;
        char aux[2];
        strcpy(aux,"");
        strncat(aux,transform[i],2);

        switch(i) {
            case 0:  printf("\n--> Encabezado MAC\nMAC DEST:  ");break;
            case 6:  printf("\nMAC ORIGEN:");break;
            case 12: printf("\nLONGITUD:  ");break;
            case 14: printf("\n\n--> Encabezado LLC\nDSAP:      ");break;
            case 15: printf("\nSSAP:      ");break;
            case 16: printf("\nControl:   ");break;
            case 17: printf("\nControl:   ");break;
        }

        if(i<18) printf(" %s ",aux);
        else break;

        int array[8];
        if(13<i && i<18) {
            int num = (int)strtol(aux, NULL, 16);
            for(j=0; j<8; j++) array[j]=0;
            int *arr=array;
            decabin(num,arr+7);
            for(j=0; j<8; j++) printf("%d",array[j]);
        }
        char protocolo[60];
        if(i==14 || i==15) {
            buscar_protocolo(aux,protocolo);
            printf(" | %s |",protocolo);
        }
        switch(i) {
            case 14:
                if(array[7]) printf("  Grupo");
                else printf("  Individual");
            break;
            case 15:
                if(array[7]) printf("  Respuesta");
                else printf("  Comando");
            break;
            case 16:
                if(array[6]==1 && array[7]==1) {
                    num_control=2;
                    int MM[] = {array[0],array[1],array[2],array[4],array[5]};
                    char info[20];
                    if(array[3]==0) printf(" |  0 --> Pull ");
                    else printf(" |  1 --> Find  ");
                    printf("  No numeradas");
                    buscar_trama_no_num(MM,info);
                    printf("\n=>  %s",info);
                }
                if(array[6]==0 && array[7]==1) {
                    num_control=1;
                    printf("  Supervision");
                    char ss[3];
                    sprintf(ss,"%d%d",array[5],array[6]);
                    printf("\n   SS= %s",ss);
                    if(strcmp(ss,"00")==0) printf(" |--> RR");
                    if(strcmp(ss,"01")==0) printf(" |--> RNR");
                    if(strcmp(ss,"10")==0) printf(" |--> Reject");
                    if(strcmp(ss,"11")==0) printf(" |--> S.Reject");
                }
                if(array[7]==0) {
                    num_control=0;
                    printf("  Informacion");
                    printf("\n   N(S)= ");
                    for(j=0; j<7; j++) printf("%d",array[j]);
                }
            break;
            case 17:
                if(num_control==0 || num_control==1) {
                    printf("\n   N(R)= ");
                    for(j=0; j<7; j++) printf("%d",array[j]);
                    if(array[7]==0) printf(" | 0 |--> Pull ");
                    else printf(" | 1 |--> Find  ");
                }
            break;
        }
    }
    printf("\n");
}

void buscar_protocolo(const char bytes[2],char protocolo[60]) {
    int i,j=0;
    int array[4];
    char binary_aux[3],new_hex[3],new_bytes[2];
    strcpy(binary_aux,"");
    strcpy(new_bytes,"");
    int num = (int)strtol(bytes[1]+"", NULL, 16);
    for(i=0; i<4; i++) array[i]=0;
    int *arr=array;
    decabin(num,arr+3);
    for(i=0; i<3; i++) sprintf(&binary_aux[j++],"%s%d",binary_aux,array[i]);
    int value = (int)strtol(binary_aux, NULL, 2);
    sprintf(new_hex,"%x",value);
    strncat(new_bytes,bytes,1);
    strcat(new_bytes,new_hex);
    strcpy(protocolo,"");
    for(i=0; i<27; i++)
        if(strcmp(protocolos[i][0],new_bytes)==0)
            strcat(protocolo,protocolos[i][1]);
}

void decabin (int n,int*array) {
    if (n) {
        *array=n%2;
        decabin(n/2,array-1);
    }
}

void buscar_trama_no_num(int*MM,char info[20]) {
    int i,j=0;
    char formato[5];
    strcpy(formato,"");
    for(i=0; i<5; i++)
        sprintf(&formato[j++],"%d",MM[i]);
    for(i=0; i<17; i++)
        if(strcmp(formato,tramas_no_num[i][0])==0)
            strcpy(info,tramas_no_num[i][1]);
}
