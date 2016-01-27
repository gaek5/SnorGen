#include "loadbar.h"
#include "flowHash.h"
#include "util.h"
#include "sequence.h"
#include "pthread.h"

#ifndef __sequenceExtracter_h
#define __sequenceExtracter_h

//######################################################################
typedef struct sThreadArg
{
	int					m_iIndex;
	int					m_iTotalThreadCount;	

	SequenceVector*		m_cpSequenceVector;
	RuleList*			m_cpCandiRuleList;
	
	RuleList			m_cpTempCandiRuleList;
	RuleList*			m_cpDetermineRuleList;
	int					m_iTrargetLength;

	u_int32_t			m_uiStartIndexTargetLength;
	u_int32_t			m_uiTargetSupp;
	u_int32_t			m_uiMaxSupp;
}THRED_ARG;


void sequence(char* p_caTargetDirectory, u_int32_t p_uiThreadCount, u_int32_t p_uiParser, u_int32_t p_uiDiffSupp, int p_iMinContentLength, int p_iMaxPktCountForward, int p_iMaxPktCountBackward, int p_iMaxSequenceLength, FILE* p_fpLogFile, char* p_caResultTextFileName, char* p_caResultFileName, char* p_caHTMLFileName);	//2014-11-01
	void *insertCandiSingle(void *arg);
	void *insertCandiMulti(void *arg);

#endif
