# requires CUTTER_SOURCE_DIR
# sets CUTTER_INCLUDE_DIRS and Cutter::Cutter

if(CUTTER_SOURCE_DIR)
	find_path(Cutter_SOURCE_ROOT
			NAMES core/Cutter.h
			PATHS "${CUTTER_SOURCE_DIR}"
			PATH_SUFFIXES src
			NO_DEFAULT_PATH)
else()
	set(Cutter_SOURCE_ROOT Cutter_SOURCE_ROOT-NOTFOUND)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Cutter
		REQUIRED_VARS Cutter_SOURCE_ROOT
		FAIL_MESSAGE "#######################################################
Could not find Cutter headers. Make sure CUTTER_SOURCE_DIR is set to the root of the Cutter source repository.
#######################################################
")

if(Cutter_FOUND)
	set(CUTTER_INCLUDE_DIRS "${Cutter_SOURCE_ROOT}" "${Cutter_SOURCE_ROOT}/common" "${Cutter_SOURCE_ROOT}/core")
	add_library(Cutter::Cutter INTERFACE IMPORTED GLOBAL)
	target_include_directories(Cutter::Cutter INTERFACE ${CUTTER_INCLUDE_DIRS})
endif()