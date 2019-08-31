
set(SOURCE
		R2GhidraPlugin.h
		R2GhidraPlugin.cpp
		R2GhidraDecompiler.h
		R2GhidraDecompiler.cpp)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)
find_package(Qt5 REQUIRED COMPONENTS Widgets Xml)

add_library(r2ghidra_cutter SHARED ${SOURCE})
target_link_libraries(r2ghidra_cutter Qt5::Widgets Qt5::Xml)
target_include_directories(r2ghidra_cutter PRIVATE "${CUTTER_SOURCE_DIR}/src" "${CUTTER_SOURCE_DIR}/src/common" "${CUTTER_SOURCE_DIR}/src/core")
target_link_libraries(r2ghidra_cutter Radare2::libr)

install(TARGETS r2ghidra_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")