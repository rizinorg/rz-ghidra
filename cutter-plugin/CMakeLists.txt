
set(SOURCE
		R2GhidraPlugin.h
		R2GhidraPlugin.cpp
		R2GhidraDecompiler.h
		R2GhidraDecompiler.cpp)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt5 REQUIRED COMPONENTS Widgets)

add_library(r2ghidra_cutter SHARED ${SOURCE})
target_link_libraries(r2ghidra_cutter Qt5::Widgets)
target_link_libraries(r2ghidra_cutter Radare2::libr)

find_package(Cutter REQUIRED)
target_link_libraries(r2ghidra_cutter Cutter::Cutter)
target_link_libraries(r2ghidra_cutter core_ghidra)

if(APPLE)
	target_link_options(r2ghidra_cutter PRIVATE -undefined dynamic_lookup)
endif()

install(TARGETS r2ghidra_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
