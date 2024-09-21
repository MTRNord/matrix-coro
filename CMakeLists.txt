cmake_minimum_required(VERSION 3.29)
project(matrix_coro)

set(CMAKE_CXX_STANDARD 23)

add_library(matrix_coro SHARED src/matrix_coro.cpp)
set_property(TARGET matrix_coro PROPERTY COMPILE_WARNING_AS_ERROR ON)

Include(FetchContent)

FetchContent_Declare(
        cppcoro
        GIT_REPOSITORY https://github.com/andreasbuhr/cppcoro.git
        GIT_TAG a4ef65281814b18fdd1ac5457d3e219347ec6cb8
        GIT_SHALLOW ON
        GIT_PROGRESS ON
)

FetchContent_MakeAvailable(cppcoro)

# Include curl
find_package(CURL REQUIRED)

# Include jsoncpp
find_package(PkgConfig REQUIRED)
pkg_check_modules(JSONCPP jsoncpp IMPORTED_TARGET GLOBAL)

if (NOT TARGET spdlog)
    find_package(spdlog REQUIRED)
endif ()

# include cthash using fetch content
FetchContent_Declare(
        cthash
        GIT_REPOSITORY https://github.com/hanickadot/cthash.git
        GIT_TAG 52ed741c82c518f7c038c50d5f39bf943067d9a8
        GIT_SHALLOW ON
        GIT_PROGRESS ON
)

FetchContent_MakeAvailable(cthash)

target_link_libraries(
        matrix_coro
        spdlog::spdlog
        PkgConfig::JSONCPP
        CURL::libcurl
        cppcoro
        cthash
)

target_include_directories(matrix_coro
        PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_CXX_CLANG_TIDY "clang-tidy")

    #set(
    #        CMAKE_CXX_FLAGS
    #        "${CMAKE_CXX_FLAGS} -fsanitize=undefined -fsanitize=address"
    #)
    #target_link_options(matrix_coro
    #        BEFORE PUBLIC -fsanitize=undefined PUBLIC -fsanitize=address
    #)
endif ()

# Examples
add_subdirectory(examples)

add_subdirectory(tests)