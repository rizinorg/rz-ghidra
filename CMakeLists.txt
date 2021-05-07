cmake_minimum_required(VERSION 3.0)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH True)

project(rz-ghidra)

set(RIZIN_INSTALL_PLUGDIR "share/rizin/plugins" CACHE STRING "Directory to install rizin plugin into")
set(CUTTER_INSTALL_PLUGDIR "share/rizin/cutter/plugins/native" CACHE STRING "Directory to install Cutter plugin into")

set(CUTTER_SOURCE_DIR CUTTER_SOURCE_DIR-NOTFOUND CACHE STRING "Root directory of Cutter source")

option(BUILD_CUTTER_PLUGIN "Build rz-ghidra plugin for Cutter" OFF)
option(BUILD_DECOMPILE_EXECUTABLE "Build \"decompile\" executable as used by Ghidra (not needed for rizin)" OFF)
option(BUILD_DECOMPILE_CLI_EXECUTABLE "Build REPL decompiler (not needed for rizin)" OFF)
option(BUILD_SLASPECS "Build Sleigh specs for architectures from Ghidra" ON)
option(BUILD_SLEIGH_PLUGIN "Build asm and analysis plugin to use sleigh as a disassembler in rizin" ON)
option(GENERATE_PARSERS "Re-generate all parsers with Bison/Flex instead of using pre-generated ones" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

if(CMAKE_VERSION VERSION_LESS "3.1")
	if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
		add_definitions(-std=c++11)
	endif()
else()
	set(CMAKE_CXX_STANDARD 11)
endif()

add_subdirectory(ghidra)
add_subdirectory(third-party)

set(PUBLIC_HEADERS
		src/rz_ghidra.h)

set(CORE_SOURCE
		src/core_ghidra.cpp
		src/RizinArchitecture.cpp
		src/RizinArchitecture.h
		src/RizinLoadImage.cpp
		src/RizinLoadImage.h
		src/RizinScope.cpp
		src/RizinScope.h
		src/RizinTypeFactory.cpp
		src/RizinTypeFactory.h
		src/RizinCommentDatabase.cpp
		src/RizinCommentDatabase.h
		src/CodeXMLParse.h
		src/CodeXMLParse.cpp
		src/ArchMap.h
		src/ArchMap.cpp
		src/RizinPrintC.h
		src/RizinPrintC.cpp
		src/RzCoreMutex.h
		src/RzCoreMutex.cpp
		src/rz_ghidra.h)

if(BUILD_SLEIGH_PLUGIN)
set(ASM_SOURCE
		src/SleighAsm.h
		src/SleighAsm.cpp
		src/SleighInstruction.h
		src/SleighInstruction.cpp
		src/asm_ghidra.cpp)

set(ANALYSIS_SOURCE
		src/SleighAsm.h
		src/SleighAsm.cpp
		src/SleighInstruction.h
		src/SleighInstruction.cpp
		src/SleighAnalysisValue.h
		src/SleighAnalysisValue.cpp
		src/analysis_ghidra.cpp)
endif()

find_package(Rizin REQUIRED)

add_library(core_ghidra SHARED ${CORE_SOURCE})
target_link_libraries(core_ghidra ghidra_libdecomp)
target_link_libraries(core_ghidra pugixml)
target_link_libraries(core_ghidra Rizin::librz)
set_target_properties(core_ghidra PROPERTIES
		OUTPUT_NAME core_ghidra
		PREFIX "")

configure_file(
	${PROJECT_SOURCE_DIR}/rz_ghidra.pc.in
	${PROJECT_BINARY_DIR}/rz_ghidra.pc
	@ONLY)

if(BUILD_CUTTER_PLUGIN)
	add_subdirectory(cutter-plugin)
endif()


if (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	string (REPLACE ";" " " LD_RPATH_STR "@loader_path")
else()
	string (REPLACE ";" " " LD_RPATH_STR "$ORIGIN")
endif()

if(BUILD_SLEIGH_PLUGIN)
add_library(asm_ghidra SHARED ${ASM_SOURCE})
target_link_libraries(asm_ghidra core_ghidra)
set_target_properties(asm_ghidra PROPERTIES
		OUTPUT_NAME asm_ghidra
		BUILD_RPATH "${LD_RPATH_STR}"
		INSTALL_RPATH "${LD_RPATH_STR}"
		PREFIX "")

add_library(analysis_ghidra SHARED ${ANALYSIS_SOURCE})
target_link_libraries(analysis_ghidra core_ghidra)
set_target_properties(analysis_ghidra PROPERTIES
		OUTPUT_NAME analysis_ghidra
		BUILD_RPATH "${LD_RPATH_STR}"
		INSTALL_RPATH "${LD_RPATH_STR}"
		PREFIX "")
endif()

if(SLEIGHHOME_DEFAULT)
	target_compile_definitions(core_ghidra PRIVATE "-DRZ_GHIDRA_SLEIGHHOME_DEFAULT=\"${SLEIGHHOME_DEFAULT}\"")
	if(BUILD_SLEIGH_PLUGIN)
		target_compile_definitions(asm_ghidra PRIVATE "-DRZ_GHIDRA_SLEIGHHOME_DEFAULT=\"${SLEIGHHOME_DEFAULT}\"")
		target_compile_definitions(analysis_ghidra PRIVATE "-DRZ_GHIDRA_SLEIGHHOME_DEFAULT=\"${SLEIGHHOME_DEFAULT}\"")
	endif()
endif()

if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
	set(CMAKE_INSTALL_LIBDIR lib CACHE PATH "Output directory for libraries.")
endif()

install(TARGETS core_ghidra DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
if(BUILD_SLEIGH_PLUGIN)
install(TARGETS asm_ghidra DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
install(TARGETS analysis_ghidra DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
endif()
install(FILES ${PUBLIC_HEADERS} DESTINATION "${CMAKE_INSTALL_PREFIX}/include")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/rz_ghidra.pc" DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
