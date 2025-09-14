cmake_minimum_required(VERSION 3.26)
project(Observathor VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Set default build type to Release for best optimization
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build (Debug or Release)" FORCE)
endif()

# Build tests only in Debug mode
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    option(OBSERVATHOR_BUILD_TESTS "Build tests" ON)
else()
    option(OBSERVATHOR_BUILD_TESTS "Build tests" OFF)
endif()

option(OBSERVATHOR_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(OBSERVATHOR_PREFER_STATIC_OPENSSL "Statically link OpenSSL when available" ON)

# Compiler-specific optimizations
if(MSVC)
    # Release: maximum optimization, no debug info
    set(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /DNDEBUG /GL")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "/LTCG /OPT:REF /OPT:ICF")
    # Debug: no optimization, full debug info
    set(CMAKE_CXX_FLAGS_DEBUG "/Od /Zi /RTC1 /MDd")
else()
    # Release: maximum optimization
    set(CMAKE_CXX_FLAGS_RELEASE "-O3 -DNDEBUG -flto")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "-flto")
    # Debug: no optimization, debug info
    set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
endif()


# Enable modules later; for now use traditional includes

include(FetchContent)

# fmt (header-only formatting) kept optional for now
set(FMT_INSTALL ON)
FetchContent_Declare(
    fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG 11.0.2
)
FetchContent_MakeAvailable(fmt)

FetchContent_Declare(
    imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG v1.90.9
)
FetchContent_MakeAvailable(imgui)

# GLFW for cross-platform window + context
FetchContent_Declare(
    glfw
    GIT_REPOSITORY https://github.com/glfw/glfw.git
    GIT_TAG 3.4
)
set(GLFW_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(GLFW_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(GLFW_INSTALL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(glfw)

add_library(observathor_core
    src/core/net/IoContext.cpp
    src/core/net/Socket.cpp
    src/core/net/UpstreamConnector.cpp
    src/core/proxy/ProxyServer.cpp
    src/core/proxy/ClientSession.cpp
    src/core/proxy/TransactionDispatcher.cpp
    src/core/proxy/TransactionLogObserver.cpp
    src/core/proxy/TransactionMemoryStore.cpp
    src/core/proxy/TransactionFileStore.cpp
    src/core/proxy/SessionSerialization.cpp
    src/core/proxy/CaptureGlobals.cpp
    src/core/http/HttpParser.cpp
    src/core/http/ChunkedDecoder.cpp
    src/core/http/HostUtil.cpp
    src/core/tls/TlsContext.cpp
    src/core/util/Logger.cpp
)

option(OBSERVATHOR_REQUIRE_OPENSSL "Fail configure if OpenSSL not found" ON)
if (OBSERVATHOR_PREFER_STATIC_OPENSSL)
    set(OPENSSL_USE_STATIC_LIBS TRUE)
endif()
if (OBSERVATHOR_REQUIRE_OPENSSL)
    find_package(OpenSSL REQUIRED)
else()
    find_package(OpenSSL QUIET)
endif()
if (OpenSSL_FOUND)
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    target_compile_definitions(observathor_core PUBLIC OBSERVATHOR_HAVE_OPENSSL=1)
    target_include_directories(observathor_core PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(observathor_core PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    if (WIN32 AND OBSERVATHOR_PREFER_STATIC_OPENSSL)
        # Static OpenSSL on Windows typically needs these system libs
        target_link_libraries(observathor_core PRIVATE ws2_32 crypt32 secur32 bcrypt user32)
    endif()
else()
    message(WARNING "OpenSSL not found; building without TLS interception support (define OBSERVATHOR_REQUIRE_OPENSSL=ON to enforce).")
endif()

target_include_directories(observathor_core PUBLIC include)
target_link_libraries(observathor_core PRIVATE fmt::fmt)

# ImGui library for UI
add_library(observathor_imgui_lib
    ${imgui_SOURCE_DIR}/imgui.cpp
    ${imgui_SOURCE_DIR}/imgui_draw.cpp
    ${imgui_SOURCE_DIR}/imgui_tables.cpp
    ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_glfw.cpp
    ${imgui_SOURCE_DIR}/backends/imgui_impl_opengl2.cpp
)
target_include_directories(observathor_imgui_lib PUBLIC 
    ${imgui_SOURCE_DIR} 
    ${imgui_SOURCE_DIR}/backends 
    ${glfw_SOURCE_DIR}/include)

if (MSVC)
    target_compile_options(observathor_core PRIVATE /permissive- /Zc:preprocessor /Zc:__cplusplus /W4)
    # Add NOMINMAX to prevent Windows.h min/max macros
    target_compile_definitions(observathor_core PRIVATE NOMINMAX)
    if (OBSERVATHOR_WARNINGS_AS_ERRORS)
        target_compile_options(observathor_core PRIVATE /WX)
    endif()
else()
    target_compile_options(observathor_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if (OBSERVATHOR_WARNINGS_AS_ERRORS)
        target_compile_options(observathor_core PRIVATE -Werror)
    endif()
endif()

# Focus on UI application - always build
add_executable(observathor_imgui apps/observathor_imgui.cpp)
target_link_libraries(observathor_imgui PRIVATE observathor_core observathor_imgui_lib glfw fmt::fmt)
if (WIN32 AND OBSERVATHOR_PREFER_STATIC_OPENSSL)
    target_link_libraries(observathor_imgui PRIVATE ws2_32 crypt32 secur32 bcrypt user32)
endif()
if (WIN32)
    target_link_libraries(observathor_imgui PRIVATE opengl32)
    # Add NOMINMAX for the UI app too
    target_compile_definitions(observathor_imgui PRIVATE NOMINMAX)
elseif(APPLE)
    find_library(COCOA_LIB Cocoa)
    find_library(IOKIT_LIB IOKit)
    find_library(COREVIDEO_LIB CoreVideo)
    target_link_libraries(observathor_imgui PRIVATE ${COCOA_LIB} ${IOKIT_LIB} ${COREVIDEO_LIB})
else()
    # On Linux glfw pulls required X11 / pthread / dl libs itself
    target_link_libraries(observathor_imgui PRIVATE GL)
endif()

# CLI application - build but not the main focus
add_executable(observathor_cli apps/observathor_cli.cpp)
target_link_libraries(observathor_cli PRIVATE observathor_core fmt::fmt)
if (WIN32 AND OBSERVATHOR_PREFER_STATIC_OPENSSL)
    target_link_libraries(observathor_cli PRIVATE ws2_32 crypt32 secur32 bcrypt user32)
endif()
if (WIN32)
    target_compile_definitions(observathor_cli PRIVATE NOMINMAX)
endif()

if (OBSERVATHOR_BUILD_TESTS)
    enable_testing()
    add_executable(smoke_test tests/smoke_test.cpp)
    target_link_libraries(smoke_test PRIVATE observathor_core fmt::fmt)
    add_test(NAME smoke COMMAND smoke_test)
    add_executable(store_test tests/store_test.cpp)
    target_link_libraries(store_test PRIVATE observathor_core fmt::fmt)
    add_test(NAME store COMMAND store_test)
    add_executable(filestore_test tests/filestore_test.cpp)
    target_link_libraries(filestore_test PRIVATE observathor_core fmt::fmt)
    add_test(NAME filestore COMMAND filestore_test)
    add_executable(chunked_test tests/chunked_test.cpp)
    target_link_libraries(chunked_test PRIVATE observathor_core fmt::fmt)
    add_test(NAME chunked COMMAND chunked_test)
    add_executable(chunked_decoder_test tests/chunked_decoder_test.cpp)
    target_link_libraries(chunked_decoder_test PRIVATE observathor_core fmt::fmt)
    add_test(NAME chunked_decoder COMMAND chunked_decoder_test)
    add_executable(tls_context_test tests/tls_context_test.cpp)
    target_link_libraries(tls_context_test PRIVATE observathor_core fmt::fmt)
    add_test(NAME tls_context COMMAND tls_context_test)
endif()
