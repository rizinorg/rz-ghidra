if(USE_SYSTEM_PUGIXML)
	find_package(pugixml REQUIRED)
else()
	add_library(pugixml STATIC
			pugixml/src/pugiconfig.hpp
			pugixml/src/pugixml.cpp
			pugixml/src/pugixml.hpp)
	target_include_directories(pugixml PUBLIC pugixml/src)
	set_target_properties(pugixml PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()

# zlib needed by ghidra for sleigh compression
if(NOT USE_SYSTEM_ZLIB)
	include(FetchContent)
	FetchContent_Declare(
		ZLIB
		URL https://raw.githubusercontent.com/rizinorg/fallback-repo/main/zlib-1.3.1.tar.gz
			https://zlib.net/fossils/zlib-1.3.1.tar.gz
		URL_HASH SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
	)
endif()
