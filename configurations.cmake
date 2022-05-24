# set output binary dir
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/Output)

# disable shared libs
set(BUILD_SHARED_LIBS OFF)

# add source directory macro
add_definitions(-DMYTEST_SRC_DIR="${CMAKE_CURRENT_SOURCE_DIR}")





