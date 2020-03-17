
enum Ambassador
{
	AMBASSADOR_PURE = 0,
	AMBASSADOR_REASON = 1,
	AMBASSADOR_REVOLUTION = 2,
	AMBASSADOR_ECHOES = 3,
	AMBASSADOR_WALL = 4,
	AMBASSADOR_MILLION = 1000000
};

struct Window
{
	const char *sunlight;
};

struct Morning
{
	uint32_t saved_argc;
	char **saved_argv;
};

struct Bright
{
	struct Morning *morning;
	struct Window window;
	enum Ambassador ambassador;
};

typedef struct Bright *BrightPtr;
typedef struct Bright BrightTypedefd;
typedef struct BrightTypedefd *BrightTypedefdPtr;
