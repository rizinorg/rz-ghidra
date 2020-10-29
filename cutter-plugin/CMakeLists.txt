
set(SOURCE
		RzGhidraPlugin.h
		RzGhidraPlugin.cpp
		RzGhidraDecompiler.h
		RzGhidraDecompiler.cpp)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt5 REQUIRED COMPONENTS Widgets)

add_library(rz_ghidra_cutter SHARED ${SOURCE})
target_link_libraries(rz_ghidra_cutter Qt5::Widgets)
target_link_libraries(rz_ghidra_cutter Rizin::librz)

find_package(Cutter REQUIRED)
target_link_libraries(rz_ghidra_cutter Cutter::Cutter)
target_link_libraries(rz_ghidra_cutter core_ghidra)

if(APPLE)
	target_link_options(rz_ghidra_cutter PRIVATE -undefined dynamic_lookup)
endif()

install(TARGETS rz_ghidra_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
