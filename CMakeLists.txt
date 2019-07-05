cmake_minimum_required(VERSION 2.8)
project(ntripcaster)

add_subdirectory(wsocket)

aux_source_directory(. SRC)
add_executable(${PROJECT_NAME} ${SRC})

target_link_libraries(${PROJECT_NAME}
	wsocket
)

