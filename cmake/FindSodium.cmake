
# - Find Sodium
# Find the native libsodium includes and library.
# Once done this will define
#
#  SODIUM_INCLUDE_DIR    - where to find libsodium header files, etc.
#  SODIUM_LIBRARY        - List of libraries when using libsodium.
#  SODIUM_FOUND          - True if libsodium found.
#

find_package(PkgConfig)
pkg_check_modules(PC_SODIUM QUIET sodium)
pkg_check_modules(PC_LSODIUM QUIET libsodium)

FIND_LIBRARY(SODIUM_LIBRARY 
    NAMES sodium libsodium 
    HINTS ${SODIUM_ROOT_DIR}/lib
          ${PC_SODIUM_LIBDIR}
          ${PC_LSODIUM_LIBDIR}
)

find_path(SODIUM_INCLUDE_DIR
    NAMES sodium.h
    HINTS ${SODIUM_ROOT_DIR}/include
          ${PC_SODIUM_INCLUDEDIR}
          ${PC_SODIUM_INCLUDE_DIRS}
          ${PC_LSODIUM_INCLUDEDIR}
          ${PC_LSODIUM_INCLUDE_DIRS}
)

# handle the QUIETLY and REQUIRED arguments and set SODIUM_FOUND to TRUE if
# all listed variables are TRUE
INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(Sodium REQUIRED_VARS SODIUM_LIBRARY SODIUM_INCLUDE_DIR)

MARK_AS_ADVANCED(SODIUM_LIBRARY SODIUM_INCLUDE_DIR)
