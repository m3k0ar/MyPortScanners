cmake_minimum_required (VERSION 3.10)
project (port_scanner)

# using c++11 standard (always a good idea)
set (CMAKE_C_STANDARD 11)

include(cmake/FindPCAP.cmake)

# enable compiler warning
# set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror -Wall -Wextra -Wpedantic")

add_executable(${PROJECT_NAME} port_scanner.c)
target_link_libraries(${PROJECT_NAME} ${PCAP_LIBRARY})