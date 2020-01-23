/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#ifndef R2GHIDRA_RCOREMUTEX_H
#define R2GHIDRA_RCOREMUTEX_H

typedef struct r_core_t RCore;

/**
 * Maintains sleep/awake state of the current r2 task like a recursive mutex
 * Use with RCoreLock for RAII behavior
 */
class RCoreMutex
{
	friend class RCoreLock;

	private:
		/**
		 * > 0 => awake
		 * == 0 => sleeping
		 */
		int caffeine_level;
		void *bed;
		RCore *_core;

	public:
		RCoreMutex(RCore *core);

		void sleepEnd();
		void sleepEndForce();
		void sleepBegin();
};

class RCoreLock
{
	private:
		RCoreMutex * const mutex;

	public:
		explicit RCoreLock(RCoreMutex *mutex) : mutex(mutex) { mutex->sleepEnd(); }
		~RCoreLock()				{ mutex->sleepBegin(); }
		operator RCore *() const	{ return mutex->_core; }
		RCore *operator->() const	{ return mutex->_core; }

};

#endif //R2GHIDRA_RCOREMUTEX_H
