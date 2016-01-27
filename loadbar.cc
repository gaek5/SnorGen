#include "loadbar.h"
//########################################################################################################
void loadBar(const char *str, int x, int n, int r, int w)
{ 
/*
	int i;
	// Only update r times.   
	if ( x % (n/r) != 0 ) return;    
	// Calculuate the ratio of complete-to-incomplete.    
	float ratio = x/(float)n;    
	int   c     = ratio * w;     
	
	// Show the percentage complete.    
	printf("%12s : %8d / %8d (%3d%%) [",str, x, n, (int)(ratio*100) );     
	// Show the load bar.    
	for ( i=0; i<c; i++)      
		printf("=");     
	for ( i=c; i<w; i++)      
		printf(" ");     
	// ANSI Control codes to go back to the   
	// previous line and clear it.    
	//printf("]\n\033[F\033[J");
	if (x!= n)
	{
		printf("]\r");
		fflush(stdout);

	}
	else
	{
		printf("]\n");
		fflush(stdout);
	}
*/	
}

//########################################################################################
int mysort(const struct dirent **a, const struct dirent **b)
{
	if (strlen((*a)->d_name)-(strlen((*b)->d_name)) != 0)
	{
		return strlen((*a)->d_name)-(strlen((*b)->d_name));

	}
	return strcmp((*a)->d_name,(*b)->d_name);
}

//########################################################################################
int isCapfile(const struct dirent *p)
{
	if (strcmp(strstr(p->d_name,"."), ".cap") == 0)  return 1;
	return 0;
}
//########################################################################################
int isPcapfile(const struct dirent *p)
{
	if (strcmp(strstr(p->d_name,"."), ".pcap") == 0)  return 1;
	return 0;
}
//########################################################################################
int isPktfile(const struct dirent *p)
{
	if (strcmp(strstr(p->d_name,"."), ".pkt") == 0)  return 1;
	return 0;
}
//########################################################################################
int isFwpfile(const struct dirent *p)
{
	if (strcmp(strstr(p->d_name,"."), ".fwp") == 0)  return 1;
	if (strcmp(strstr(p->d_name,"."), ".fwpr") == 0)  return 1;
	return 0;
}
//########################################################################################
int isSigfile(const struct dirent *p)
{
	if (strcmp(strstr(p->d_name,"."), ".xml") == 0)  return 1;
	return 0;
}
//########################################################################################
int isTrafficfile(const struct dirent *p)
{
	if (!strstr(p->d_name,".")) return 0;

	if (strcmp(strstr(p->d_name,"."), ".cap") == 0)  return 1;
	if (strcmp(strstr(p->d_name,"."), ".pcap") == 0)  return 1;
	return 0;
}
//########################################################################################
int isTextfile(const struct dirent *p)
{
	if (strcmp(strstr(p->d_name,"."), ".txt") == 0)  return 1;
	return 0;
}







//########################################################################################
int selfile_pcaptopkt(const struct dirent *p)
{
	if (strstr(p->d_name, ".pcap")) return 1;
	return 0;
}
//########################################################################################
int selfile_pkttoflow(const struct dirent *p)
{
	if (strstr(p->d_name, "pkt_")) return 1;
	return 0;
}
//########################################################################################
int selfile_pkttoflowwithpkt(const struct dirent *p)
{
	if (strstr(p->d_name, ".pkt")) return 1;
	return 0;
}
//########################################################################################
int selfile_flowwithpkt(const struct dirent *p)
{
	if (strstr(p->d_name, ".fwp")) return 1;
	return 0;
}
//########################################################################################
int selfile_all(const struct dirent *p)
{
	if (strcmp(p->d_name, ".")==0) return 0;
	if (strcmp(p->d_name, "..")==0) return 0;
	return 1;
}
//########################################################################################
int selfile_all_except_ok(const struct dirent *p)
{
	if (strcmp(p->d_name, ".")==0) return 0;
	if (strcmp(p->d_name, "..")==0) return 0;
	if (strstr(p->d_name, "ok")) return 0;
	return 1;
}
