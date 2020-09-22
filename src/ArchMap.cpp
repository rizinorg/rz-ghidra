/* radare - LGPL - Copyright 2019 - thestr4ng3r */

#include "ArchMap.h"
#include <error.hh>
#include <map>
#include <functional>

std::string CompilerFromCore(RCore *core);

template<typename T>
class BaseMapper
{
	private:
		const std::function<T(RCore *)> func;
	public:
		BaseMapper(const std::function<T(RCore *)> &func) : func(func) {}
		BaseMapper(const T constant) : func([constant](RCore *core) { return constant; }) {}
		T Map(RCore *core) const { return func(core); }
};

template<typename T> class Mapper;
template<> class Mapper<ut64> : public BaseMapper<ut64> { public: using BaseMapper<ut64>::BaseMapper; };
template<> class Mapper<bool> : public BaseMapper<bool> { public: using BaseMapper<bool>::BaseMapper; };

template<> class Mapper<std::string> : public BaseMapper<std::string>
{
	public:
		using BaseMapper<std::string>::BaseMapper;
		Mapper<std::string>(const char *constant) : BaseMapper([constant](RCore *core) { return constant; }) {}
};

static const Mapper<bool> big_endian_mapper_default = std::function<bool(RCore *)>([](RCore *core) { return r_config_get_i(core->config, "cfg.bigendian") != 0; });
static const Mapper<ut64> bits_mapper_default = std::function<ut64(RCore *)>([](RCore *core) { return r_config_get_i(core->config, "asm.bits"); });

class ArchMapper
{
	private:
		const Mapper<std::string> arch;
		const Mapper<std::string> flavor;
		const Mapper<bool> big_endian;
		const Mapper<ut64> bits;

	public:
		ArchMapper(
				const Mapper<std::string> arch,
				const Mapper<std::string> flavor = "default",
				const Mapper<ut64> bits = bits_mapper_default,
				const Mapper<bool> big_endian = big_endian_mapper_default)
			: arch(arch), flavor(flavor), bits(bits), big_endian(big_endian) {}

		std::string Map(RCore *core) const
		{
			return arch.Map(core)
				+ ":" + (big_endian.Map(core) ? "BE" : "LE")
				+ ":" + to_string(bits.Map(core))
				+ ":" + flavor.Map(core)
				+ ":" + CompilerFromCore(core);
		}
};

#define BITS (r_config_get_i(core->config, "asm.bits"))
#define CUSTOM_BASEID(lambda) std::function<std::string(RCore *)>([]lambda)
#define CUSTOM_FLAVOR(lambda) std::function<std::string(RCore *)>([]lambda)
#define CUSTOM_BITS(lambda) std::function<ut64(RCore *)>([]lambda)

// keys = asm.arch values
static const std::map<std::string, ArchMapper> arch_map = {
	{ "x86", {
		"x86",
		CUSTOM_FLAVOR((RCore *core) {
			return BITS == 16 ? "Real Mode" : "default";
		})}},

	{ "mips", { "MIPS" } },
	{ "dalvik", { "Dalvik" } },
	{ "6502", { "6502", "default", 16 } },
	{ "java", { "JVM", "default", bits_mapper_default, true } },
	{ "hppa", { "pa-risc" } },
	{ "ppc", { "PowerPC" } },
	{ "sparc", { "sparc" } },
	{ "sh", { "SuperH4" } },
	{ "msp430", { "TI_MSP430" } },
	{ "m68k", {
		"68000",
		CUSTOM_FLAVOR((RCore *core) {
			const char *cpu = r_config_get(core->config, "asm.cpu");
			if(!cpu)
				return "default";
			if(strcmp(cpu, "68020") == 0)
				return "MC68020";
			if(strcmp(cpu, "68030") == 0)
				return "MC68030";
			if(strcmp(cpu, "68060") == 0)
				return "Coldfire"; // may not be accurate!!
			return "default";
		}),
		32 } },

	{ "arm", {
	 	CUSTOM_BASEID((RCore *core) {
			return BITS == 64 ? "AARCH64" : "ARM";
		}),
		CUSTOM_FLAVOR((RCore *core) {
			return BITS == 64 ? "v8A" : "v7";
		}),
		CUSTOM_BITS((RCore *core) {
			return BITS == 64 ? 64 : 32;
		})}},

	{ "avr", {
		CUSTOM_BASEID((RCore *core) {
			return BITS == 32 ? "avr32a" : "avr8";
		}),
		"default",
		CUSTOM_BITS((RCore *core) {
			return BITS == 32 ? 32 : 16;
		})}},

	{ "v850", {
		CUSTOM_BASEID((RCore *core) {
			return "V850";
		}),
		"default",
		CUSTOM_BITS((RCore *core) {
			return 32;
		})}},
};

static const std::map<std::string, std::string> compiler_map = {
	{ "elf", "gcc" },
	{ "pe", "windows" },
	{ "mach0", "gcc" }
};

std::string CompilerFromCore(RCore *core)
{
	RBinInfo *info = r_bin_get_info(core->bin);
	if (!info || !info->rclass)
		return std::string();

	auto comp_it = compiler_map.find(info->rclass);
	if(comp_it == compiler_map.end())
		return std::string();

	return comp_it->second;
}

std::string SleighIdFromCore(RCore *core)
{
	const char *arch = r_config_get(core->config, "asm.arch");
	auto arch_it = arch_map.find(arch);
	if(arch_it == arch_map.end()) {
		char *cpu = strdup (r_config_get(core->config, "asm.cpu"));
		char *colon = cpu;
		while (*colon) {
			if (*colon == ':') {
				*colon = 0;
				break;
			}
			*colon = tolower (*colon);
			colon++;
		}
		arch_it = arch_map.find(cpu);
		free (cpu);
		if(arch_it == arch_map.end()) {
			throw LowlevelError("Could not match asm.arch " + std::string(arch) + " to sleigh arch.");
		}
	}
	return arch_it->second.Map(core);
}
