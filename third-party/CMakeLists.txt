
add_library(pugixml STATIC
		pugixml/src/pugiconfig.hpp
		pugixml/src/pugixml.cpp
		pugixml/src/pugixml.hpp)
target_include_directories(pugixml PUBLIC pugixml/src)
set_target_properties(pugixml PROPERTIES POSITION_INDEPENDENT_CODE ON)

