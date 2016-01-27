#include <pcap.h>

#include "packet.h"

#ifndef __PcapReader_h
#define __PcapReader_h

#define MAXSTR	256

#define ETHER_LENGTH	14
#define CRC_LENGTH		4
#define PKT_LENGTH		(1518 - CRC_LENGTH)
#define IP_LENGTH		(1518 - CRC_LENGTH - ETHER_LENGTH)
//##################################################################################################
class PcapReader
{
public:
	pcap_t				*m_pcap_input;


public:
	PcapReader(void){memset(this, 0, sizeof(PcapReader));};
	PcapReader(PcapReader *r){memcpy(this, r, sizeof(PcapReader));};
	~PcapReader(void){};

	void reset(){memset(this, 0, sizeof(PcapReader));};
	void set(PcapReader* r){memcpy(this, r, sizeof(PcapReader));};

	
	void offlineFileOpen(char *outfile);
	void offlineFileClose();

	unsigned char* readPkt(PacketStoredInfo *pktInfo);
	

	void print();
	void printDetail();
};




#endif

