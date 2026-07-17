cmake_minimum_required(VERSION 3.16)
project(sampleclib VERSION 1.0.0 LANGUAGES C)

add_library(sampleclib STATIC src/sample.c)
target_include_directories(sampleclib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
set_target_properties(sampleclib PROPERTIES PUBLIC_HEADER include/sample.h)

option(BUILD_TESTING "Build consumer test" ON)
if(BUILD_TESTING)
    add_executable(sample_consumer tests/sample_consumer.c)
    target_link_libraries(sample_consumer PRIVATE sampleclib)
endif()

install(TARGETS sampleclib
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
)
