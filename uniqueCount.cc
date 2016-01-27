//######################################################################
//
//		uniqueCount.cc
//		programmed by jinwan park
//		2010.01.04
//
//######################################################################

#include "include.h"
#include "uniqueCount.h"

//######################################################################
UniqueCount::UniqueCount()
{
	memset(this, 0, sizeof(UniqueCount));
}


//######################################################################
UniqueCount::~UniqueCount()
{
	reset();

	delete head;
}


//######################################################################
void UniqueCount::reset()
{
	
	UniqueContainer *target;

	if ( head == NULL )	return;

	while ( head->next )
	{
		target = head->next;
		head->next = target->next;

		delete target;
		target = NULL;
	}

	head = 0;
	count = 0;

}


//######################################################################
int UniqueCount::insert( int val1)
{
	
	UniqueContainer *go;

	for ( go = head;  go && !(go->val1 == val1);  go = go->next );

	if ( go == NULL )
	{
		go = new UniqueContainer;

		go->val1 = val1;
		go->id = ++count;

		go->next = head;
		head = go;
	}
	return go->id;
}
//######################################################################
void UniqueCount::print()
{
	
	UniqueContainer *go;
	int recordCount=0;

	for ( go = head;  go ;  go = go->next )
	{
		recordCount++;
		printf("%d  ",go->val1);
	}
	printf("\n");

	if (count != recordCount)
	{
		printf("real %d, count %d Differ\n");
		exit(0);
	}

}
//######################################################################
void UniqueCount::update(UniqueCount *p_cpUniqueCount)
{
	UniqueContainer *go;

	for ( go = p_cpUniqueCount->head;  go ;  go = go->next )
	{
		insert(go->val1);
	}
}










