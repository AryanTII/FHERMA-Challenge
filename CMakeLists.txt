cmake_minimum_required(VERSION 3.5.1)
project(OpenFHESort CXX)
set(CMAKE_CXX_STANDARD 17)
option( BUILD_STATIC "Set to ON to include static versions of the library" OFF)

find_package(OpenFHE REQUIRED)

set( CMAKE_CXX_FLAGS ${OpenFHE_CXX_FLAGS} )

include_directories( ${OPENMP_INCLUDES} )
include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories(${OpenFHE_INCLUDE}/binfhe)

link_directories( ${OpenFHE_LIBDIR} )
link_directories( ${OPENMP_LIBRARIES} )
link_directories(${OpenFHE_LIBRARY_DIRS})
link_directories(/usr/local/lib)


if(BUILD_STATIC)
    set( CMAKE_EXE_LINKER_FLAGS "${OpenFHE_EXE_LINKER_FLAGS} -static")
    link_libraries( ${OpenFHE_STATIC_LIBRARIES} )
else()
    set( CMAKE_EXE_LINKER_FLAGS ${OpenFHE_EXE_LINKER_FLAGS} )
    link_libraries( ${OpenFHE_SHARED_LIBRARIES} )
endif()

add_executable(app main.cpp sort_ckks.h sort_ckks.cpp helper.h helper.cpp)
target_link_libraries(app ${LIBRARIES})
