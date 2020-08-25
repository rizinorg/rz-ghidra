
typedef struct LinkedList *LL;

struct LinkedList {
	uint32_t data;
	uint32_t padding;
	LL next;
};
