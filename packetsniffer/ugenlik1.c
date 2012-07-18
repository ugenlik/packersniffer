/**********************************************************************
* Umut Can Genlik
* Description: 
*
*   Large amounts of this code were taken from tcpdump source
*   namely the following files..
*
*   print-ether.c
*   print-ip.c
*   ip.h
*
* Compile with:
* gcc -Wall -pedantic disect2.c -lpcap (-o foo_err_something) 
*
* Usage:
* a.out (# of packets) "filter string"
*
**********************************************************************/


#ifdef LINUX
#include <netinet/ether.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include<string.h> //for memset
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> 
#include <net/ethernet.h>



#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header


#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <netinet/ip.h> 

/* tcpdump header (ether.h) defines ETHER_HDRLEN) */
#ifndef ETHER_HDRLEN 
#define ETHER_HDRLEN 14
#endif

FILE *logfile;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j; 



u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);
u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet);


/*
 * Structure of an internet header, naked of options.
 *
 * Stolen from tcpdump source (thanks tcpdump people)
 *
 * We declare ip_len and ip_off to be short, rather than u_short
 * pragmatically since otherwise unsigned comparisons can result
 * against negative integers quite easily, and fail in subtle ways.
 */
struct my_ip {
	u_int8_t	ip_vhl;		/* header length, version */
#define IP_V(ip)	(((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ip_vhl & 0x0f)
	u_int8_t	ip_tos;		/* type of service */
	u_int16_t	ip_len;		/* total length */
	u_int16_t	ip_id;		/* identification */
	u_int16_t	ip_off;		/* fragment offset field */
#define	IP_DF 0x4000			/* dont fragment flag */
#define	IP_MF 0x2000			/* more fragments flag */
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
	u_int8_t	ip_ttl;		/* time to live */
	u_int8_t	ip_p;		/* protocol */
	u_int16_t	ip_sum;		/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};


struct nread_tcp {
    u_short th_sport; /* source port            */
    u_short th_dport; /* destination port       */
    u_long th_seq;   /* sequence number        */
    u_long th_ack;   /* acknowledgement number */
#if BYTE_ORDER == LITTLE_ENDIAN
    u_int th_x2:4,    /* (unused)    */
th_off:4;         /* data offset */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    u_int th_off:4,   /* data offset */
th_x2:4;          /* (unused)    */
#endif
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};


/* looking at ethernet headers */
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    u_int16_t type = handle_ethernet(args,pkthdr,packet);

    if(type == ETHERTYPE_IP)
    {/* handle IP packet */
        handle_IP(args,pkthdr,packet);
    }else if(type == ETHERTYPE_ARP)
    {/* handle arp packet */
    }
    else if(type == ETHERTYPE_REVARP)
    {/* handle reverse arp packet */
    }
}

u_char* handle_IP
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    const struct my_ip* ip;
    const struct nread_tcp* tcp; // tcp structure
    u_int length = pkthdr->len;
    u_int hlen,off,version;
    

    int len;

    /* jump pass the ethernet header */
    ip = (struct my_ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header); 

    tcp = (struct nread_tcp*)(packet + sizeof(struct ether_header) +
                              sizeof(struct my_ip));
    
    
    
    /* check to see we have a packet of valid length */
    if (length < sizeof(struct my_ip))
    {
        printf("truncated ip %d",length);
        fprintf(logfile,"truncated ip %d",length);
        return NULL;
    }

    len     = ntohs(ip->ip_len);
    hlen    = IP_HL(ip); /* header length */
    version = IP_V(ip);/* ip version */

    /* check version */
    if(version != 4)
    {
      fprintf(stdout,"Unknown version %d\n",version);
        fprintf(logfile,"Unknown version %d\n",version);
      return NULL;
    }

    /* check header length */
    if(hlen < 5 )
    {
        fprintf(stdout,"bad-hlen %d \n",hlen);
            fprintf(logfile,"bad-hlen %d \n",hlen);
    }

    /* see if we have as much packet as we should */
    if(length < len)
        printf("\ntruncated IP - %d bytes missing\n",len - length);
            fprintf(logfile,"\ntruncated IP - %d bytes missing\n",len - length);

    /* Check to see if we have the first fragment */
    off = ntohs(ip->ip_off);
    if((off & 0x1fff) == 0 )/* aka no 1's in first 13 bits */
    {/* print SOURCE DESTINATION hlen version len offset */
        fprintf(stdout,"IP: ");
            fprintf(logfile,"IP: ");
        
        fprintf(stdout,"Source %s: Destination %u->%s:%u\n ",
                inet_ntoa(ip->ip_src), tcp->th_sport,
                inet_ntoa(ip->ip_dst), tcp->th_dport);
        
            fprintf(logfile,"Source %s: Destination %u->%s:%u\n  ",
                inet_ntoa(ip->ip_src), tcp->th_sport,
                inet_ntoa(ip->ip_dst), tcp->th_dport);
        
        /*fprintf(stdout,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),hlen,version,len,off);
        
            fprintf(logfile,"%s %d %d %d %d\n",
                inet_ntoa(ip->ip_dst),hlen,version,len,off); */
        
        
        fprintf(stdout,
                "Type of Service: %u Length of Ip Header : %u\n Fragment offset Field :%u\n Time to live: %u\n Protocol: %u\n Checksum: %u\n ",
                ip->ip_tos, len, off, ip->ip_ttl,
                ip->ip_p, ip->ip_sum);
        
            fprintf(logfile,
                "Type of Service: %u Length of Ip Header : %u\n Fragment offset Field :%u\n Time to live: %u\n Protocol: %u\n Checksum: %u\n ",
                ip->ip_tos, len, off, ip->ip_ttl,
                ip->ip_p, ip->ip_sum);
        
        
        fprintf(stdout,"Sequence Number: %lo\n Nack Sequence: %lo\nWindow: %ho\n",
                tcp->th_seq, tcp->th_ack, tcp->th_win);
            
            fprintf(logfile,"Sequence Number: %lo\n Nack Sequence: %lo\nWindow: %ho\n",
                tcp->th_seq, tcp->th_ack, tcp->th_win);
        //fprintf(stdout,"%s", payload);
        printf("========================================================\n");
    }
    

    return NULL;
}

/* handle ethernet packets, much of this code gleaned from
 * print-ether.c from tcpdump source
 */
u_int16_t handle_ethernet
        (u_char *args,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    u_int caplen = pkthdr->caplen;
    u_int length = pkthdr->len;
    struct ether_header *eptr;  /* net/ethernet.h */
    u_short ether_type;

    if (caplen < ETHER_HDRLEN)
    {
        fprintf(stdout,"Packet length less than ethernet header length\n");
            fprintf(logfile,"Packet length less than ethernet header length\n");
        return -1;
    }

    /* lets start with the ether header... */
    eptr = (struct ether_header *) packet;
    ether_type = ntohs(eptr->ether_type);

    /* Lets print SOURCE DEST TYPE LENGTH */
    fprintf(stdout,"ETH: ");
        fprintf(logfile,"ETH: ");
    
    fprintf(stdout,"Source: %s \n"
            ,ether_ntoa((struct ether_addr*)eptr->ether_shost));
        fprintf(logfile,"Source: %s\n "
            ,ether_ntoa((struct ether_addr*)eptr->ether_shost));    
    
    fprintf(stdout,"Destination: %s \n"
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));
    
    fprintf(logfile,"Destination: %s \n"
            ,ether_ntoa((struct ether_addr*)eptr->ether_dhost));

    /* check to see if we have an ip packet */
    if (ether_type == ETHERTYPE_IP)
    {
        fprintf(stdout,"Type = (IP)\n");
            fprintf(logfile,"Type = (IP)\n");
    }else  if (ether_type == ETHERTYPE_ARP)
    {
        fprintf(stdout,"Type = (ARP)\n");
            fprintf(logfile,"Type = (ARP)\n");
        
    }else  if (eptr->ether_type == ETHERTYPE_REVARP)
    {
        fprintf(stdout,"Type = (RARP)\n");
            fprintf(logfile,"Type = (RARP)\n");
    }else {
        fprintf(stdout,"Type = (others)\n");
            fprintf(logfile,"Type = (others)\n");
    }
    fprintf(stdout,"  Length %d\n",length);
        fprintf(logfile,"Length %d\n",length);
    return ether_type;
}


int main(int argc,char **argv)
{ 
    char *dev="en1";  /* make this null if device is not Mac OSX */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;      /* hold compiled program     */
    bpf_u_int32 maskp;          /* subnet mask               */
    bpf_u_int32 netp;           /* ip                        */
    u_char* args = NULL;

    char filename[64];
    int i;
    
    
    /* Options must be passed in as a string because I am lazy */
    if(argc < 2){ 
        fprintf(stdout,"Usage: %s numpackets \"options\"\n",argv[0]);
        return 0;
    }
    
   
    
    printf("Write a file name with extension : ");
	scanf("%s", filename);
	
	/* open file with given name */
	logfile = fopen(filename, "w");
    
    if(logfile==NULL)
    {
        printf("Unable to create file.");
        exit(1);
    }
    
    
    /* grab a device to peak into... */
    /*dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); } */

    
    
    
    /* ask pcap for the network address and mask of the device */
    pcap_lookupnet(dev,&netp,&maskp,errbuf);

    /* open device for reading. NOTE: defaulting to
     * promiscuous mode*/
    descr = pcap_open_live(dev,BUFSIZ,1,0,errbuf);
    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }


    if(argc > 2)
    {
        /* Lets try and compile the program.. non-optimized */
        if(pcap_compile(descr,&fp,argv[2],0,netp) == -1)
        { fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

        /* set the compiled program as the filter */
        if(pcap_setfilter(descr,&fp) == -1)
        { fprintf(stderr,"Error setting filter\n"); exit(1); }
    }
    
    
    printf("========================================================\n");
	fprintf(logfile, "========================================================\n");
    
    while (1) {
    
    /* ... and loop */ 
    pcap_loop(descr,atoi(argv[1]),my_callback,args);
        
        printf("Do you want continue to sniff? If Yes Enter= 1 , If No Enter=2, O to exit = \n");
        scanf("%d",&i);
        
        
        
        if(i==2){
            
            FILE *file = fopen ( filename, "r" );
            
            if ( file != NULL )
            {
                char line [ 128 ]; /* or other suitable maximum line size */
                while ( fgets ( line, sizeof line, file ) != NULL ) /* read a line */
                {
                    fputs ( line, stdout ); /* write the line */
                }
                fclose ( file );
            }
            else
            {
                perror ( filename ); /* why didn't the file open? */
            }
        
        }
        
        
        else if(i==0)
        {
            break;
        }
    }

    fclose(logfile);
    fprintf(stdout,"\nfinished\n");
    return 0;
}

