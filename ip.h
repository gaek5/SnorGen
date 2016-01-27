/**************************************************************************** 
** File: ip.h
**
** Author: Mike Borella, Hong Soon-Hwa
**
** Comments: Generic IP header structure - an attempt at OS independence
**
*****************************************************************************/

#ifndef __IP_h
#define __IP_h

#include <sys/types.h>// u_int8_t, ... 
#include <netinet/in.h>// struct in_addr

typedef struct _IPHdr
{
#if defined(WORDS_BIGENDIAN)
  u_int8_t    ip_v:4, 
              ip_hl:4;
#else
  u_int8_t    ip_hl:4, 
              ip_v:4;
#endif
  u_int8_t    ip_tos;
  u_int16_t   ip_len;
  u_int16_t   ip_id;
  u_int16_t   ip_off;
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */

  u_int8_t    ip_ttl;
  u_int8_t    ip_proto;
  u_int16_t   ip_csum;
  struct in_addr   ip_src;
  struct in_addr   ip_dst;
} IPHdr;


#define IP_PROTO_ICMP		1		/* control message protocol */
#define IP_PROTO_IGMP		2		/* group mgmt protocol */
#define IP_PROTO_TCP		6		/* tcp */
#define IP_PROTO_UDP		17		/* user datagram protocol */
#define IP_PROTO_EIGRP		88

/*
#define ICMP_NEXT_HEADER 1
#define IP_NEXT_HEADER   4
#define TCP_NEXT_HEADER  6
#define UDP_NEXT_HEADER  17
#define GRE_MEXT_HEADER  47
#define ESP_NEXT_HEADER  50
#define AH_NEXT_HEADER   51
*/

/*
#define IPPROTO_ICMP	1
#define IP_NEXT_HEADER   4
#define IPPROTO_TCP		6
#define IPPROTO_UDP		17
#define GRE_MEXT_HEADER  47
#define ESP_NEXT_HEADER  50
#define AH_NEXT_HEADER   51
*/

//#define IP_PROTO_IP		0		/* dummy for IP */
//#define IP_PROTO_HOPOPTS	0		/* IP6 hop-by-hop options */
//#define IP_PROTO_ICMP		1		/* control message protocol */
//#define IP_PROTO_IGMP		2		/* group mgmt protocol */
//#define IP_PROTO_GGP		3		/* gateway^2 (deprecated) */
//#define IP_PROTO_IPIP		4		/* IP inside IP */
//#define IP_PROTO_IPV4		4		/* IP header */
//#define IP_PROTO_TCP		6		/* tcp */
//#define IP_PROTO_EGP		8		/* exterior gateway protocol */
//#define IP_PROTO_PUP		12		/* pup */
//#define IP_PROTO_UDP		17		/* user datagram protocol */
//#define IP_PROTO_IDP		22		/* xns idp */
//#define IP_PROTO_TP		29 		/* tp-4 w/ class negotiation */
//#define IP_PROTO_IPV6		41		/* IP6 header */
//#define IP_PROTO_ROUTING	43		/* IP6 routing header */
//#define IP_PROTO_FRAGMENT	44		/* IP6 fragmentation header */
//#define IP_PROTO_RSVP     46              /* Resource ReSerVation protocol */
//#define IP_PROTO_GRE		47		/* GRE */
//#define IP_PROTO_ESP		50		/* ESP */
//#define IP_PROTO_AH		51		/* AH */
//#define IP_PROTO_ICMPV6	58		/* ICMP6 */
//#define IP_PROTO_DSTOPTS	60		/* IP6 no next header */
//#define IP_PROTO_EON		80		/* ISO cnlp */
//#define IP_PROTO_VINES	83		/* Vines over raw IP */
//#define IP_PROTO_EIGRP	88
//#define IP_PROTO_OSPF		89
//#define IP_PROTO_ENCAP	98		/* encapsulation header */
//#define IP_PROTO_PIM		103		/* Protocol Independent Mcast */
//#define IP_PROTO_IPCOMP	108		/* IP payload compression */
//#define IP_PROTO_VRRP		112		/* Virtual Router Redundancy Protocol */
//#define IP_PROTO_SCTP     132             /* Stream Control Transmission Protocol */


#endif