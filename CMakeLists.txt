cmake_minimum_required(VERSION 3.1.0)
project(mkudns LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/Modules")
include(MkUtils)

# Download dependencies
# ---------------------

MkDownloadAdishavitArgh()
MkDownloadNlohmannJson()
MkDownloadMeasurementKitMkData()

# TODO(bassosimone): add unit tests and use Catch2
#MkDownloadCatchorgCatch2()

# TODO(bassosimone): update the code to use mkmock
#MkDownloadMeasurementKitMkMock()

# TODO(bassosimone): here we should download prebuilt c-ares for Windows
#if("${MSVC}")
#  MkDownloadMeasurementKitPrebuiltWindowsCurl()
#  list(APPEND CMAKE_INCLUDE_PATH "${MK_WINDOWS_CURL_INCLUDE_PATH}")
#  list(APPEND CMAKE_LIBRARY_PATH "${MK_WINDOWS_CURL_LIBRARY_PATH}")
#  add_definitions(${MK_WINDOWS_CURL_DEFINITIONS})
#  list(APPEND MKUDNS_LIBS ${MK_WINDOWS_CURL_EXTRA_LINK_LIBS})
#endif()

# Checks
# ------

# TODO(bassosimone): here we should search for c-ares
#find_package(CURL REQUIRED)

# TODO(bassosimone): here we should properly search for OpenSSL
if("${APPLE}")
  list(APPEND INCLUDES_ "/usr/local/Cellar/libressl/2.8.2/include")
  list(APPEND LIBS_ "/usr/local/Cellar/libressl/2.8.2/lib/libcrypto.dylib")
else()
  list(APPEND LIBS_ "crypto")
endif()

# Compiler flags
# --------------

MkSetCompilerFlags()

# Library and binary
# ------------------

set(MKUDNS_INCLUDES ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_REQUIRED_INCLUDES} ${INCLUDES_})
include_directories(${MKUDNS_INCLUDES})

# TODO(bassosimone): make this code portable and portably search for cares
list (APPEND MKUDNS_LIBS "cares" ${LIBS_})
if("${WIN32}" OR "${MINGW}")
  list(APPEND MKUDNS_LIBS "ws2_32")
  if ("${MINGW}")
      list(APPEND MKUDNS_LIBS -static-libgcc -static-libstdc++)
  endif()
endif()
list(APPEND MKUDNS_LIBS Threads::Threads)
link_libraries("${MKUDNS_LIBS}")

add_library(mkudns mkudns.cpp)
add_executable(mkudns-client mkudns-client.cpp)
target_link_libraries(mkudns-client mkudns)

# Testing
# -------

set(BUILD_TESTING "ON" CACHE BOOL "Whether to build tests")
if(${BUILD_TESTING})
  # TODO(bassosimone): add unit and integration tests
# add_executable(unit-tests unit-tests.cpp)
# if("${WIN32}")
#   target_compile_options(unit-tests PRIVATE /EHs)  # exceptions in extern "C"
# endif()
# add_executable(integration-tests integration-tests.cpp)
# target_link_libraries(integration-tests mkudns)
  enable_testing()
# add_test(NAME unit_tests COMMAND unit-tests)
# add_test(NAME integration_tests COMMAND integration-tests)
  add_test(NAME resolve_youtube COMMAND
           mkudns-client --server-address 9.9.9.9 www.youtube.com)
endif()
