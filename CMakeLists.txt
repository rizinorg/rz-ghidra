cmake_minimum_required(VERSION 3.0)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH True)

project(r2ghidra)

set(RADARE2_INSTALL_PLUGDIR "share/radare2/plugins" CACHE PATH "Directory to install radare2 plugin into")
set(CUTTER_INSTALL_PLUGDIR "share/RadareOrg/Cutter/plugins/native" CACHE PATH "Directory to install Cutter plugin into")

set(CUTTER_SOURCE_DIR CUTTER_SOURCE_DIR-NOTFOUND CACHE STRING "Root directory of Cutter source")

option(BUILD_CUTTER_PLUGIN "Build r2ghidra plugin for Cutter" OFF)
option(BUILD_DECOMPILE_EXECUTABLE "Build \"decompile\" executable as used by Ghidra (not needed for r2)" OFF)
option(BUILD_DECOMPILE_CLI_EXECUTABLE "Build REPL decompiler (not needed for r2)" OFF)
option(BUILD_SLASPECS "Build Sleigh specs for architectures from Ghidra" ON)

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

set(SOURCE
		src/core_ghidra.cpp
		src/R2Architecture.cpp
		src/R2Architecture.h
		src/R2LoadImage.cpp
		src/R2LoadImage.h
		src/R2Scope.cpp
		src/R2Scope.h
		src/R2TypeFactory.cpp
		src/R2TypeFactory.h
		src/R2CommentDatabase.cpp
		src/R2CommentDatabase.h
		src/CodeXMLParse.h
		src/CodeXMLParse.cpp
		src/ArchMap.h
		src/ArchMap.cpp
		src/R2PrintC.h
		src/R2PrintC.cpp
		src/RCoreMutex.h
		src/RCoreMutex.cpp)

find_package(Radare2 REQUIRED)

if(BUILD_CUTTER_PLUGIN)
	add_subdirectory(cutter-plugin)
endif()

add_library(core_ghidra SHARED ${SOURCE})
target_link_libraries(core_ghidra ghidra_decompiler_base ghidra_libdecomp ghidra_decompiler_sleigh)
target_link_libraries(core_ghidra pugixml)
target_link_libraries(core_ghidra Radare2::libr)
set_target_properties(core_ghidra PROPERTIES
		OUTPUT_NAME core_ghidra
		PREFIX "")

if(SLEIGHHOME_DEFAULT)
	target_compile_definitions(core_ghidra PRIVATE "-DR2GHIDRA_SLEIGHHOME_DEFAULT=\"${SLEIGHHOME_DEFAULT}\"")
endif()

install(TARGETS core_ghidra DESTINATION "${RADARE2_INSTALL_PLUGDIR}")