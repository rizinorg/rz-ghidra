
#include <stdint.h>
#include <stdbool.h>

#include "types_rec.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct LinkedList *BuildList()
{
	struct LinkedList *l = NULL;
	for(uint32_t i=0; i<50; i++)
	{
		struct LinkedList *p = l;
		l = malloc(sizeof(struct LinkedList));
		l->data = i;
		l->next = p;
	}
}

void KillList(struct LinkedList *l)
{
	while(l)
	{
		struct LinkedList *n = l->next;
		free(l);
		l = n;
	}
}

int main(int argc, char **argv)
{
	KillList(BuildList());
	return 0;
}

