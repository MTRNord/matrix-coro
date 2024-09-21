add_executable(
        matrix_coro_example
        main.cpp
)

target_link_libraries(
        matrix_coro_example
        matrix_coro
        cppcoro
        spdlog::spdlog
)