cmake_minimum_required(VERSION 3.16)
project(zcap_test C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Platform-specific settings
if(WIN32)
    # Windows requires different DLL export macros
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS LIBZCAP_EXPORTS)
else()
    add_compile_definitions()
endif()

# Find the libzcap library
find_library(ZCAP_LIBRARY zcap PATHS ${CMAKE_SOURCE_DIR}/../zig-out/lib)
find_path(ZCAP_INCLUDE_DIR libzcap.h PATHS ${CMAKE_SOURCE_DIR}/../include)

if(NOT ZCAP_LIBRARY)
    message(WARNING "zcap library not found, building from source")
    # Build libzcap as part of this project
    find_package(Zig REQUIRED)
    
    # Build libzcap.a from Zig sources
    add_custom_target(zcap_lib ALL
        COMMAND ${ZIG_EXECUTABLE} build-lib 
            -fno-entry 
            --name zcap 
            --target native 
            ${CMAKE_SOURCE_DIR}/../src/lib.zig
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/..
        OUTPUT_VARIABLE ZCAP_LIBRARY
    )
    
    set(ZCAP_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/../include)
endif()

include_directories(${ZCAP_INCLUDE_DIR})
link_directories(${${ZCAP_LIBRARY}}/../lib)

add_executable(zcap_test 
    test_pcap.c
)

if(ZCAP_LIBRARY)
    if(WIN32)
        target_link_libraries(zcap_test PRIVATE ${ZCAP_LIBRARY}.lib)
    else()
        target_link_libraries(zcap_test PRIVATE ${ZCAP_LIBRARY})
    endif()
else()
    add_dependencies(zcap_test zcap_lib)
endif()

# Copy test pcap files
file(COPY ${CMAKE_SOURCE_DIR}/../src/test/testzcap/msglog_001001_20260323_122248.pcap 
     DESTINATION ${CMAKE_BINARY_DIR})
