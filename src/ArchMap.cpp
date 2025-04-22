// SPDX-FileCopyrightText: 2019-2021 Florian Märkl <info@florianmaerkl.de>
// SPDX-FileCopyrightText: 2019 Ayman Khamouma <kamou.k@gmail.com>
// SPDX-License-Identifier: LGPL-3.0-or-later

#include "ArchMap.h"
#include <error.hh>
#include <map>
#include <functional>

using namespace ghidra;

std::string CompilerFromCore(RzCore *core);

template <typename T> class BaseMapper {
    private:
	const std::function<T(RzCore *)> func;

    public:
	BaseMapper(const std::function<T(RzCore *)> &func)
		: func(func)
	{
	}
	BaseMapper(const T constant)
		: func([constant](RzCore *core) { return constant; })
	{
	}
	T Map(RzCore *core) const
	{
		return func(core);
	}
};

template <typename T> class Mapper;
template <> class Mapper<ut64> : public BaseMapper<ut64> {
    public:
	using BaseMapper<ut64>::BaseMapper;
};
template <> class Mapper<bool> : public BaseMapper<bool> {
    public:
	using BaseMapper<bool>::BaseMapper;
};

template <> class Mapper<std::string> : public BaseMapper<std::string> {
    public:
	using BaseMapper<std::string>::BaseMapper;
	Mapper<std::string>(const char *constant)
		: BaseMapper([constant](RzCore *core) { return constant; })
	{
	}
};

static const Mapper<bool> big_endian_mapper_default =
	std::function<bool(RzCore *)>([](RzCore *core) {
		return rz_config_get_i(core->config, "cfg.bigendian") != 0;
	});
static const Mapper<ut64> bits_mapper_default = std::function<ut64(RzCore *)>(
	[](RzCore *core) { return rz_config_get_i(core->config, "asm.bits"); });

class ArchMapper {
    private:
	const Mapper<std::string> arch;
	const Mapper<std::string> flavor;
	const Mapper<bool> big_endian;
	const Mapper<ut64> bits;

    public:
	ArchMapper(const Mapper<std::string> arch,
		   const Mapper<std::string> flavor = "default",
		   const Mapper<ut64> bits = bits_mapper_default,
		   const Mapper<bool> big_endian = big_endian_mapper_default)
		: arch(arch)
		, flavor(flavor)
		, bits(bits)
		, big_endian(big_endian)
	{
	}

	std::string Map(RzCore *core) const
	{
		return arch.Map(core) + ":" +
		       (big_endian.Map(core) ? "BE" : "LE") + ":" +
		       to_string(bits.Map(core)) + ":" + flavor.Map(core) +
		       ":" + CompilerFromCore(core);
	}
};

#define BITS (rz_config_get_i(core->config, "asm.bits"))
#define CUSTOM_BASEID(lambda) std::function<std::string(RzCore *)>([] lambda)
#define CUSTOM_FLAVOR(lambda) std::function<std::string(RzCore *)>([] lambda)
#define CUSTOM_BITS(lambda) std::function<ut64(RzCore *)>([] lambda)

// keys = asm.arch values
static const std::map<std::string, ArchMapper> arch_map = {
	{ "x86", { "x86", CUSTOM_FLAVOR((RzCore *core) {
			   return BITS == 16 ? "Real Mode" : "default";
		   }) } },

	{ "mips", { "MIPS" } },
	{ "dalvik", { "Dalvik" } },
	{ "6502", { "6502", "default", 16 } },
	{ "8051", { "8051", "default", 16, true } },
	{ "java", { "JVM", "default", bits_mapper_default, true } },
	{ "hppa", { "pa-risc" } },
	{ "ppc", { "PowerPC" } },
	{ "sparc", { "sparc" } },
	{ "sh", { "SuperH4" } },
	{ "msp430", { "TI_MSP430" } },
	{ "m68k",
	  { "68000", CUSTOM_FLAVOR((RzCore *core) {
		    const char *cpu = rz_config_get(core->config, "asm.cpu");
		    if (!cpu)
			    return "default";
		    if (strcmp(cpu, "68020") == 0)
			    return "MC68020";
		    if (strcmp(cpu, "68030") == 0)
			    return "MC68030";
		    if (strcmp(cpu, "68060") == 0)
			    return "Coldfire"; // may not be accurate!!
		    return "default";
	    }),
	    32 } },

	{ "arm",
	  { CUSTOM_BASEID(
		    (RzCore *core) { return BITS == 64 ? "AARCH64" : "ARM"; }),
	    CUSTOM_FLAVOR((RzCore *core) { return BITS == 64 ? "v8A" : "v7"; }),
	    CUSTOM_BITS((RzCore *core) { return BITS == 64 ? 64 : 32; }) } },

	{ "avr",
	  { CUSTOM_BASEID(
		    (RzCore *core) { return BITS == 32 ? "avr32a" : "avr8"; }),
	    "default",
	    CUSTOM_BITS((RzCore *core) { return BITS == 32 ? 32 : 16; }) } },

	{ "v850",
	  { CUSTOM_BASEID((RzCore *core) { return "V850"; }), "default",
	    CUSTOM_BITS((RzCore *core) { return 32; }) } },

	{ "tricore", { "tricore" } },

	{ "pic",
	  {
		  CUSTOM_BASEID((RzCore *core) {
			  const char *cpu =
				  rz_config_get(core->config, "analysis.cpu");
			  if (RZ_STR_EQ(cpu, "pic14")) {
				  return "PIC-12";
			  }
			  if (RZ_STR_EQ(cpu, "pic16")) {
				  return "PIC-16";
			  }
			  return "PIC-18";
		  }),
		  CUSTOM_BASEID((RzCore *core) {
			  const char *cpu =
				  rz_config_get(core->config, "analysis.cpu");
			  if (RZ_STR_EQ(cpu, "pic14")) {
				  return "PIC-12C5xx";
			  }
			  if (RZ_STR_EQ(cpu, "pic16")) {
				  return "PIC-16F";
			  }
			  return "PIC-18";
		  }),
		  CUSTOM_BITS((RzCore *core) {
			  const char *cpu =
				  rz_config_get(core->config, "analysis.cpu");
			  if (RZ_STR_EQ(cpu, "pic18")) {
				  return 24;
			  }
			  return 16;
		  }),
	  } },
};

static const std::map<std::string, std::string> compiler_map = {
	{ "elf", "gcc" },
	{ "pe", "windows" },
	{ "mach0", "gcc" }
};

std::string CompilerFromCore(RzCore *core)
{
	RzBinObject *bobj = rz_bin_cur_object(core->bin);
	if (!bobj)
		return std::string();
	const RzBinInfo *info = rz_bin_object_get_info(bobj);
	if (!info || !info->rclass)
		return std::string();

	auto comp_it = compiler_map.find(info->rclass);
	if (comp_it == compiler_map.end())
		return std::string();

	return comp_it->second;
}

RZ_API std::string SleighIdFromCore(RzCore *core)
{
	SleighArchitecture::collectSpecFiles(std::cerr);
	auto langs = SleighArchitecture::getLanguageDescriptions();
	const char *arch = rz_config_get(core->config, "asm.arch");
	if (!strcmp(arch, "ghidra"))
		return SleighIdFromSleighAsmConfig(core->rasm->cpu,
						   core->rasm->bits,
						   core->rasm->big_endian,
						   langs);
	auto arch_it = arch_map.find(arch);
	if (arch_it == arch_map.end())
		throw LowlevelError("Could not match asm.arch " +
				    std::string(arch) + " to sleigh arch.");
	return arch_it->second.Map(core);
}

std::string StrToLower(std::string s)
{
	std::transform(s.begin(), s.end(), s.begin(),
		       [](unsigned char c) { return std::tolower(c); });
	return s;
}

RZ_API std::string
SleighIdFromSleighAsmConfig(const char *cpu, int bits, bool bigendian,
			    const vector<LanguageDescription> &langs)
{
	if (!cpu)
		return std::string();
	if (std::string(cpu).find(':') != string::npos) // complete id specified
		return cpu;
	// short form if possible
	std::string low_cpu = StrToLower(cpu);
	for (const auto &lang : langs) {
		auto proc = lang.getProcessor();
		if (StrToLower(proc) == low_cpu) {
			return proc + ":" + (bigendian ? "BE" : "LE") + ":" +
			       to_string(bits) + ":" + "default";
		}
	}
	return cpu;
}
