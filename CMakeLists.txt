cmake_minimum_required(VERSION 3.12)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

add_subdirectory(ghidra)

set(SOURCE
		src/core_ghidra.cpp)

find_package(Radare2 REQUIRED)

add_library(core_ghidra SHARED ${SOURCE})
set_target_properties(core_ghidra PROPERTIES
		OUTPUT_NAME core_ghidra
		PREFIX "")
target_link_directories(core_ghidra PRIVATE ${RADARE2_LIBRARY_DIRS})
target_link_libraries(core_ghidra ${RADARE2_LIBRARIES})
target_include_directories(core_ghidra PRIVATE ${RADARE2_INCLUDE_DIRS})