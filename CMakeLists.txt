cmake_minimum_required(VERSION 3.12)

project(r2ghidra)

option(BUILD_CUTTER_PLUGIN "Build r2ghidra plugin for Cutter" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

set(CMAKE_CXX_STANDARD 11)

add_subdirectory(ghidra)

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
		src/R2Printc.cpp
		src/R2Printc.h
        src/R2Emit.cpp
        src/R2Emit.h)

find_package(Radare2 REQUIRED)

if(BUILD_CUTTER_PLUGIN)
	add_subdirectory(cutter-plugin)
endif()

add_library(core_ghidra SHARED ${SOURCE})
target_link_libraries(core_ghidra ghidra_decompiler_base ghidra_libdecomp ghidra_decompiler_sleigh)
set_target_properties(core_ghidra PROPERTIES
		OUTPUT_NAME core_ghidra
		PREFIX "")
target_link_libraries(core_ghidra Radare2::libr)
