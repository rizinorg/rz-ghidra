
set(SOURCE
		RzGhidraPlugin.h
		RzGhidraPlugin.cpp
		RzGhidraDecompiler.h
		RzGhidraDecompiler.cpp)

set(CMAKE_AUTOMOC ON)
add_library(rz_ghidra_cutter MODULE ${SOURCE})
target_link_libraries(rz_ghidra_cutter Cutter::Cutter)
target_link_libraries(rz_ghidra_cutter core_ghidra)
install(TARGETS rz_ghidra_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
