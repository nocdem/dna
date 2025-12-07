# Libjuice.cmake - libjuice NAT Traversal Library
#
# Builds libjuice as an ExternalProject for ICE/STUN NAT traversal.
# Replaces libnice + glib (no glib dependency, simpler cross-compilation).
#
# Sets: JUICE_INCLUDE_DIRS, JUICE_LIBRARIES, libjuice target

include(ExternalProject)

# Create include directory at configure time to avoid CMake errors
file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/vendor/libjuice/install/include)

# Build libjuice external project with platform-specific settings
set(LIBJUICE_CMAKE_ARGS
    -DCMAKE_INSTALL_PREFIX=${CMAKE_BINARY_DIR}/vendor/libjuice/install
    -DCMAKE_BUILD_TYPE=Release
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON
    -DBUILD_SHARED_LIBS=OFF
    -DUSE_NETTLE=OFF
    -DNO_TESTS=ON
)

# Pass toolchain and Android settings for cross-compilation
if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND LIBJUICE_CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
endif()
if(ANDROID)
    list(APPEND LIBJUICE_CMAKE_ARGS
        -DANDROID_ABI=${ANDROID_ABI}
        -DANDROID_PLATFORM=${ANDROID_PLATFORM}
        -DANDROID_STL=c++_static
    )
endif()

ExternalProject_Add(libjuice_external
    GIT_REPOSITORY https://github.com/paullouisageneau/libjuice.git
    GIT_TAG v1.7.0
    PREFIX ${CMAKE_BINARY_DIR}/vendor/libjuice
    CMAKE_ARGS ${LIBJUICE_CMAKE_ARGS}
    BUILD_BYPRODUCTS ${CMAKE_BINARY_DIR}/vendor/libjuice/install/lib/${CMAKE_STATIC_LIBRARY_PREFIX}juice${CMAKE_STATIC_LIBRARY_SUFFIX}
    LOG_DOWNLOAD ON
    LOG_CONFIGURE ON
    LOG_BUILD ON
)

# Create imported target for libjuice
add_library(libjuice STATIC IMPORTED GLOBAL)
add_dependencies(libjuice libjuice_external)
set_target_properties(libjuice PROPERTIES
    IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/vendor/libjuice/install/lib/${CMAKE_STATIC_LIBRARY_PREFIX}juice${CMAKE_STATIC_LIBRARY_SUFFIX}
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_BINARY_DIR}/vendor/libjuice/install/include
)

set(JUICE_INCLUDE_DIRS ${CMAKE_BINARY_DIR}/vendor/libjuice/install/include)
set(JUICE_LIBRARIES libjuice)
message(STATUS "libjuice will be built from source (v1.7.0)")
