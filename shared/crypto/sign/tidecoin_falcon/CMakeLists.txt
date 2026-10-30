cmake_minimum_required(VERSION 3.16)
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  project(qgp_tidecoin_falcon C)
endif()
set(tidecoin_sources
  upstream/pq/fips202.c upstream/pq/falcon512.c
  upstream/pq/falcon-512/codec.c upstream/pq/falcon-512/common.c
  upstream/pq/falcon-512/fft.c upstream/pq/falcon-512/fpr.c
  upstream/pq/falcon-512/keygen.c upstream/pq/falcon-512/pqclean.c
  upstream/pq/falcon-512/rng.c upstream/pq/falcon-512/sign.c
  upstream/pq/falcon-512/vrfy.c)
add_library(qgp_tidecoin_falcon STATIC qgp_tidecoin_falcon.c ${tidecoin_sources})
set_target_properties(qgp_tidecoin_falcon PROPERTIES C_STANDARD 11
  C_STANDARD_REQUIRED YES C_EXTENSIONS NO POSITION_INDEPENDENT_CODE YES
  C_VISIBILITY_PRESET hidden)
target_include_directories(qgp_tidecoin_falcon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(qgp_tidecoin_falcon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/upstream)
if(MSVC)
  target_compile_options(qgp_tidecoin_falcon PRIVATE /FI${CMAKE_CURRENT_SOURCE_DIR}/private_namespace.h)
else()
  target_compile_options(qgp_tidecoin_falcon PRIVATE
    -include ${CMAKE_CURRENT_SOURCE_DIR}/private_namespace.h)
  target_link_libraries(qgp_tidecoin_falcon PUBLIC m)
endif()
