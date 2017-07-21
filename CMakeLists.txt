cmake_minimum_required(VERSION 2.6)
project(typroto)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++1z")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu11")

if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, default to Release")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    if (NOT ENABLE_SEC)
        message(STATUS "CANARY , PIE , RELRO , FORTIFY not enabled, if you have enough performance (laptop/pc/server) / memory (>2MB) , and want to protect against pwning  , please enable it by -DENABLE_SEC=1")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
    else()
        if (WIN32)
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions --param=ssp-buffer-size=4")
        else()
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-all -D_FORTIFY_SOURCE=2 -O2")
            if (APPLE)
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIE -Wl,-pie")
            else()
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wl,-z,relro,-z,now -fPIE -pie")
            endif()
        endif()
    endif()
endif()


set(CMAKE_C_FLAGS_DEBUG "-DDEBUG -g")

file(GLOB SOURCE_FILES
    "src/*.h"
    "src/*.c"
    "src/*.hpp"
    "src/*.cpp"
)

if (NOT CMAKE_CROSSCOMPILING)
    include_directories(/usr/local/include)
    link_directories(/usr/local/lib)
endif()

if (CMAKE_CROSSCOMPILING AND APPLE)
    find_package(ZLIB REQUIRED)
endif()
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Sodium REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR} ${SODIUM_INCLUDE_DIR})

enable_testing()

add_library(${PROJECT_NAME} SHARED ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME} ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES} ${SODIUM_LIBRARY} m)
if (WIN32)
    target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
endif()
if (CMAKE_CROSSCOMPILING AND APPLE)
    target_link_libraries(${PROJECT_NAME} ${ZLIB_LIBRARIES})
endif()

add_library(${PROJECT_NAME}_static STATIC ${SOURCE_FILES})
target_link_libraries(${PROJECT_NAME}_static ${CMAKE_THREAD_LIBS_INIT} ${OPENSSL_LIBRARIES} ${SODIUM_LIBRARY} m)
set_target_properties(${PROJECT_NAME}_static PROPERTIES OUTPUT_NAME ${PROJECT_NAME})


install(DIRECTORY src/ DESTINATION include/typroto
        FILES_MATCHING PATTERN "*.h")

install(TARGETS ${PROJECT_NAME} ${PROJECT_NAME}_static DESTINATION lib)

add_custom_target(uninstall
    "${CMAKE_COMMAND}" -P "${CMAKE_MODULE_PATH}/uninstall.cmake"
)
if (NOT CMAKE_CROSSCOMPILING)
add_executable(tperf_client tools/tperf_client.c)
target_link_libraries(tperf_client ${PROJECT_NAME})

add_executable(tperf_server tools/tperf_server.c)
target_link_libraries(tperf_server ${PROJECT_NAME})

add_executable(gen_key tools/gen_key.c)
target_link_libraries(gen_key ${OPENSSL_LIBRARIES})



add_executable(test_box_packet tests/test_pkt.c)
target_link_libraries(test_box_packet ${PROJECT_NAME})

add_executable(test_handshake tests/test_hs.c)
target_link_libraries(test_handshake ${PROJECT_NAME})

add_executable(test_network tests/test_network.c)
target_link_libraries(test_network ${PROJECT_NAME})

add_executable(test_stress tests/test_stress.c)
target_link_libraries(test_stress ${PROJECT_NAME})

add_test(NAME test_box_packet COMMAND ./test_box_packet)
add_test(NAME test_handshake COMMAND ./test_handshake)
add_test(NAME test_network COMMAND ./test_network)
add_test(NAME test_stress COMMAND ./test_stress)
endif()