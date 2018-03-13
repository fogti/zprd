# derived from: https://github.com/zserik/zsdatab/FindZsdatable.cmake.in

# - Try to find Intel TBB
# Once done, this will define
#
#  TBB_FOUND - system has TBB
#  TBB_INCLUDE_DIRS - the TBB include directories
#  TBB_LIBRARIES - link these to use TBB
#  TBB_DEFINITIONS - compiler switches required for using TBB

include(CMakeFindDependencyMacro)
find_package(PkgConfig)

pkg_check_modules(PC_TBB QUIET tbb)
set(TBB_DEFINITIONS ${PC_TBB_CFLAGS_OTHER})

find_path(TBB_INCLUDE_DIR
  NAMES tbb/tbb.h
  PATHS ${PC_TBB_INCLUDEDIR} ${PC_TBB_INCLUDE_DIRS}
)

find_library(TBB_LIBRARY
  NAMES tbb
  PATHS ${PC_TBB_LIBDIR} ${PC_TBB_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(TBB DEFAULT_MSG TBB_LIBRARY TBB_INCLUDE_DIR)

mark_as_advanced(TBB_INCLUDE_DIR TBB_LIBRARY)

set(TBB_INCLUDE_DIRS ${TBB_INCLUDE_DIR})
set(TBB_LIBRARIES ${TBB_LIBRARY})
