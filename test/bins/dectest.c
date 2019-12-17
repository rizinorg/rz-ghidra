
#include <stdint.h>
#include <stdbool.h>

#include "types.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t global_var = 42;

uint32_t get_global_var() {
	return global_var;
}

uint32_t global_array[2] = { 1337, 123 };

uint32_t get_global_array_entry() {
	return global_array[1];
}


void Aeropause(struct Bright *bright, int argc, char **argv);

int main(int argc, char **argv)
{
	struct Bright bright;
	Aeropause(&bright, argc, argv);
	return 0;
}

static inline void PrintAmbassador(enum Ambassador ambassador)
{
	printf("Ambassador value: ");
	switch(ambassador)
	{
		case AMBASSADOR_PURE:
			printf("pure");
			break;
		case AMBASSADOR_REASON:
			printf("reason");
			break;
		case AMBASSADOR_REVOLUTION:
			printf("revolution");
			break;
		case AMBASSADOR_ECHOES:
			printf("echoes");
			break;
		case AMBASSADOR_WALL:
			printf("wall");
			break;
		case AMBASSADOR_MILLION:
			printf("million");
			break;
		default:
			break;
	}
	printf("\n");
}

void Aeropause(struct Bright *bright, int argc, char **argv)
{
	bright->morning = malloc(sizeof(struct Morning));
	bright->morning->saved_argc = argc;
	bright->morning->saved_argv = argv;
	if(bright->morning->saved_argc < 2)
	{
		bright->ambassador = AMBASSADOR_PURE;
	}
	else
	{
		bright->window.sunlight = bright->morning->saved_argv[1];
		if(strcmp(bright->window.sunlight, "the  ") == 0)
			bright->ambassador = AMBASSADOR_REASON;
		else if(strcmp(bright->window.sunlight, "dark") == 0)
			bright->ambassador = AMBASSADOR_REVOLUTION;
		else if(strcmp(bright->window.sunlight, "third") == 0)
			bright->ambassador = AMBASSADOR_ECHOES;
		else
			bright->ambassador = AMBASSADOR_MILLION;
	}
	switch(bright->ambassador)
	{
		case AMBASSADOR_PURE:
			printf("pure");
			break;
		case AMBASSADOR_REASON:
			printf("reason");
			break;
		case AMBASSADOR_REVOLUTION:
			printf("revolution");
			break;
		case AMBASSADOR_ECHOES:
			printf("echoes");
			break;
		case AMBASSADOR_WALL:
			printf("wall");
			break;
		case AMBASSADOR_MILLION:
			printf("million");
			break;
		default:
			break;
	}
	PrintAmbassador(bright->ambassador);
}

