cmake_minimum_required(VERSION 2.8)
project(ntripcaster)
set(CMAKE_C_STANDARD 99)

add_subdirectory(wsocket)
add_subdirectory(ulog)
add_subdirectory(cJSON)

IF(WIN32)
add_executable(${PROJECT_NAME} ntripcaster.c evwrap.c)
target_link_libraries(${PROJECT_NAME}
	wsocket
	ulog
	cJSON
)
ELSE()
add_executable(${PROJECT_NAME} ntripcaster.c)
target_link_libraries(${PROJECT_NAME}
	wsocket
	ulog
	cJSON
	ev
)
ENDIF()

