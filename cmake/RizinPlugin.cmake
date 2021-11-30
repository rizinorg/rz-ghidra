# defines RIZIN_INSTALL_PLUGDIR_DEFAULT

set(install_prefix_tmp "${CMAKE_INSTALL_PREFIX}")
set(CMAKE_INSTALL_PREFIX /usr) # Make GNUInstallDirs append the arch triple on Debian
include(GNUInstallDirs)
set(CMAKE_INSTALL_PREFIX "${install_prefix_tmp}")
if(NOT DEFINED CMAKE_INSTALL_LIBDIR)
	set(CMAKE_INSTALL_LIBDIR lib)
endif()
set(RIZIN_INSTALL_PLUGDIR "${CMAKE_INSTALL_LIBDIR}/rizin/plugins" CACHE STRING "Directory to install rizin plugins into")
