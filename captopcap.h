#include "loadbar.h"
#include "util.h"

#ifndef __captopcap_h
#define __captopcap_h
void convertFromCapToPcap(char* p_caCurrentWorkingDirectory, char *p_cpDataPath, char *p_cpCapPath, u_int32_t p_uiSnapLen, u_int32_t p_uiTrial_num, char *p_cpPcapPath); // cap 형태의 트래픽을 pcap 형태로 변환
void convertFromCapToPcap(char* p_caTargetDirectory); // cap or pcap 형태의 트래픽을 pcap 형태로 변환
void convertFromCapToPcap(char* p_caTargetDirectory, FILE* p_fpLogFile); // 파일 1개 이하 에러, capinfos 명령어로 trace 검증
#endif
