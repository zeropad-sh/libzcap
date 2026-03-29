cmake_minimum_required(VERSION 3.16)
project(libzcap_examples LANGUAGES C CXX)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(LIBZCAP_ROOT "${CMAKE_CURRENT_LIST_DIR}/.." CACHE PATH "Path to the libzcap checkout")
set(LIBZCAP_BUILD_DIR "${LIBZCAP_ROOT}/zig-out" CACHE PATH "Path containing built libzcap artifacts")

if (WIN32)
    set(_ZCAP_CANDIDATES
        "lib/libzcap.dll"
        "lib/zcap.dll"
        "lib/libzcap.dll.a"
        "lib/zcap.dll.a"
        "lib/libzcap.lib"
        "lib/zcap.lib"
        "bin/zcap.dll"
        "bin/libzcap.dll"
    )
else()
    set(_ZCAP_CANDIDATES
        "lib/libzcap.so"
        "lib/libzcap.dylib"
        "lib/libzcap.a"
    )
endif()

set(ZCAP_LIBRARY "")
foreach(_candidate IN LISTS _ZCAP_CANDIDATES)
    if (EXISTS "${LIBZCAP_BUILD_DIR}/${_candidate}") 
        set(ZCAP_LIBRARY "${LIBZCAP_BUILD_DIR}/${_candidate}")
        break()
    endif()
endforeach()

if (NOT ZCAP_LIBRARY)
    if (WIN32)
        find_library(
            ZCAP_LIBRARY
            NAMES zcap zcap.lib zcap.dll.a libzcap libzcap.lib libzcap.dll.a
            PATHS "${LIBZCAP_BUILD_DIR}" "${LIBZCAP_BUILD_DIR}/lib" "${LIBZCAP_BUILD_DIR}/bin"
            NO_DEFAULT_PATH
        )
    else()
        find_library(
            ZCAP_LIBRARY
            NAMES zcap libzcap
            PATHS "${LIBZCAP_BUILD_DIR}" "${LIBZCAP_BUILD_DIR}/lib"
            NO_DEFAULT_PATH
        )
    endif()
endif()

if (NOT ZCAP_LIBRARY OR ZCAP_LIBRARY STREQUAL "ZCAP_LIBRARY-NOTFOUND")
    if (WIN32)
        message(FATAL_ERROR "Could not find a libzcap import target in ${LIBZCAP_BUILD_DIR}. Run 'zig build' first, and make sure it produces zcap.dll/zcap.lib or zcap.dll.a.")
    else()
        message(FATAL_ERROR "Could not find libzcap in ${LIBZCAP_BUILD_DIR}. Run 'zig build' first, or set LIBZCAP_BUILD_DIR explicitly.")
    endif()
endif()

include_directories("${LIBZCAP_ROOT}/include")

set(C_EXAMPLES
    01_basic_capture.c
    02_pcap_dump.c
    04_bpf_filter.c
    05_next_and_stats.c
    06_filtered_capture_to_file.c
    08_offline_protocol_stats.c
    10_live_capture_options.c
    11_findalldevs_lookupdev.c
    12_nonblocking_stats.c
    13_send_packet.c
    18_async_select.c
    20_linux_kernel_features.c
)

set(CPP_EXAMPLES
    03_offline_read.cpp
    07_offline_split_ipv4.cpp
    09_offline_split_transport.cpp
    15_findalldevs_lookupdev.cpp
    16_nonblocking_stats.cpp
    17_send_packet.cpp
    18_async_select.cpp
    19_async_native_wait.cpp
)

foreach(src IN LISTS C_EXAMPLES)
    get_filename_component(name ${src} NAME_WE)
    set(target_name "${name}_c")
    add_executable(${target_name} ${src})
    target_link_libraries(${target_name} PRIVATE ${ZCAP_LIBRARY})
endforeach()

foreach(src IN LISTS CPP_EXAMPLES)
    get_filename_component(name ${src} NAME_WE)
    set(target_name "${name}_cpp")
    add_executable(${target_name} ${src})
    target_link_libraries(${target_name} PRIVATE ${ZCAP_LIBRARY})
endforeach()
