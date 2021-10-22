// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-License-Identifier: LGPL-3.0-or-later

#ifndef RZ_GHIDRA_RZCOREMUTEX_H
#define RZ_GHIDRA_RZCOREMUTEX_H

typedef struct rz_core_t RzCore;

/**
 * Maintains sleep/awake state of the current rizin task like a recursive mutex
 * Use with RzCoreLock for RAII behavior
 */
class RzCoreMutex
{
	friend class RzCoreLock;

	private:
		/**
		 * > 0 => awake
		 * == 0 => sleeping
		 */
		int caffeine_level;
		void *bed;
		RzCore *_core;

	public:
		RzCoreMutex(RzCore *core);

		void sleepEnd();
		void sleepEndForce();
		void sleepBegin();
};

class RzCoreLock
{
	private:
		RzCoreMutex * const mutex;

	public:
		explicit RzCoreLock(RzCoreMutex *mutex) : mutex(mutex) { mutex->sleepEnd(); }
		~RzCoreLock()				{ mutex->sleepBegin(); }
		operator RzCore *() const	{ return mutex->_core; }
		RzCore *operator->() const	{ return mutex->_core; }

};

#endif //RZ_GHIDRA_RCOREMUTEX_H
