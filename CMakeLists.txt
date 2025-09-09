cmake_minimum_required(VERSION 3.26)
project(Observathor VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(OBSERVATHOR_BUILD_TESTS "Build tests" ON)
option(OBSERVATHOR_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(OBSERVATHOR_ENABLE_IMGUI "Build ImGui prototype UI" OFF)

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

if (OBSERVATHOR_ENABLE_IMGUI)
    FetchContent_Declare(
        imgui
        GIT_REPOSITORY https://github.com/ocornut/imgui.git
        GIT_TAG v1.90.9
    )
    FetchContent_MakeAvailable(imgui)
endif()

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
    src/core/http/HttpParser.cpp
    src/core/http/HostUtil.cpp
    src/core/util/Logger.cpp
)

set_target_properties(observathor_core PROPERTIES OUTPUT_NAME observathor_core)

target_include_directories(observathor_core PUBLIC include)

target_link_libraries(observathor_core PRIVATE fmt::fmt)

if (OBSERVATHOR_ENABLE_IMGUI)
    add_library(observathor_imgui_lib
        ${imgui_SOURCE_DIR}/imgui.cpp
        ${imgui_SOURCE_DIR}/imgui_draw.cpp
        ${imgui_SOURCE_DIR}/imgui_tables.cpp
        ${imgui_SOURCE_DIR}/imgui_widgets.cpp
    )
    target_include_directories(observathor_imgui_lib PUBLIC ${imgui_SOURCE_DIR} ${imgui_SOURCE_DIR}/backends)
    # SDL2 + OpenGL loader left for future; placeholder executable will not link these backends yet.
    add_executable(observathor_imgui apps/observathor_imgui_stub.cpp)
    target_link_libraries(observathor_imgui PRIVATE observathor_core observathor_imgui_lib fmt::fmt)
endif()

if (MSVC)
    target_compile_options(observathor_core PRIVATE /permissive- /Zc:preprocessor /Zc:__cplusplus /W4)
    if (OBSERVATHOR_WARNINGS_AS_ERRORS)
        target_compile_options(observathor_core PRIVATE /WX)
    endif()
else()
    target_compile_options(observathor_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion)
    if (OBSERVATHOR_WARNINGS_AS_ERRORS)
        target_compile_options(observathor_core PRIVATE -Werror)
    endif()
endif()

add_executable(observathor_cli apps/observathor_cli.cpp)

target_link_libraries(observathor_cli PRIVATE observathor_core fmt::fmt)

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
endif()
