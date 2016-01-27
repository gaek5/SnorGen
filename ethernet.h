/**************************************************************************** 
** File: ethernet.h
**
** Author: Mike Borella, Hong Soon-Hwa
**
** Comments: Generic ethernet structure - an attempt at OS independence
*****************************************************************************/

#include <sys/types.h>// u_int8_t, ...

#define ETHERTYPE_IP            0x0800  /* IP protocol */
#define ETHERTYPE_ARP           0x0806  /* Addr. resolution protocol */
#define ETHERTYPE_RARP          0x8035  /* reverse Addr. resolution protocol */
#define ETHERTYPE_IPX           0x8137  /* IPX family */
#define ETHERTYPE_NETBIOS		0x8191  /* NetBios Protocol*/
#define ETHERTYPE_OTHERS		0x0000

#define ETHER_MTU               1500


#define SAP_IP				0x06  /* IP protocol */
#define SAP_BPDU			0x42  /* IPX family */
#define SAP_SNAP            0xaa  /* SAP SNAP */
#define SAP_IPX				0xe0  /* IPX family */
#define SAP_NETBIOS			0xf0  /* NetBios */
//#define SAP_GLOBAL			0xff  /*SAP-GLOBALS*/
#define SAP_OTHERS			0x0000




typedef struct _EtherHdr
{
  unsigned char  ether_dst[6];
  unsigned char  ether_src[6];
  unsigned short ether_type;
} EtherHdr;

/* ether_type < 1500보다 작은 것을 처리하기 위해 */
typedef struct _EtherHdr_1042
{
  unsigned char  ether_dst[6];
  unsigned char  ether_src[6];
  unsigned short len;
//  unsigned char llc[6];

  u_int8_t dsap;
  u_int8_t ssap;
  u_int8_t cntl;
  	
  u_int8_t org[3];
//  u_int16_t pid;	
  //unsigned short  aaa[3];
  unsigned short ether_type;
} EtherHdr_1042;


//void dump_ethernet(u_char *user, const struct pcap_pkthdr *h, u_char *p);





