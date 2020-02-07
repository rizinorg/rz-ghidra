option(USE_SYSTEM_PUGIXML "Use system pugixml library" OFF)

if (USE_SYSTEM_PUGIXML)
	find_package(pugixml REQUIRED)
else()
	add_library(pugixml STATIC
			pugixml/src/pugiconfig.hpp
			pugixml/src/pugixml.cpp
			pugixml/src/pugixml.hpp)
	target_include_directories(pugixml PUBLIC pugixml/src)
	set_target_properties(pugixml PROPERTIES POSITION_INDEPENDENT_CODE ON)
endif()
