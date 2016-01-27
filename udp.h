/**************************************************************************** 
** File: udp.h
**
** Author: Mike Borella
**
** Comments: Generic UDP header structure - an attempt at OS independence
**
*****************************************************************************/

/*
#define L2TP_PORT 1701

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define SIP_PORT 5060
#define RIP_PORT 520
#define ISAKMP_PORT 500
*/

/*
typedef struct _UDPHdr
{
  u_int16_t uh_src;
  u_int16_t uh_dst;
  u_int16_t uh_len;
  u_int16_t uh_chk;
} UDPHdr;
*/

typedef struct _UDPHdr
{
  u_int16_t src_port;
  u_int16_t dst_port;
  u_int16_t len;
  u_int16_t chk_sum;
} UDPHdr;
