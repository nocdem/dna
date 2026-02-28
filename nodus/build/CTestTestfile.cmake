# CMake generated Testfile for 
# Source directory: /opt/dna/nodus
# Build directory: /opt/dna/nodus/build
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_cbor "/opt/dna/nodus/build/test_cbor")
set_tests_properties(test_cbor PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;142;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_wire "/opt/dna/nodus/build/test_wire")
set_tests_properties(test_wire PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;147;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_value "/opt/dna/nodus/build/test_value")
set_tests_properties(test_value PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;152;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_identity "/opt/dna/nodus/build/test_identity")
set_tests_properties(test_identity PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;157;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_routing "/opt/dna/nodus/build/test_routing")
set_tests_properties(test_routing PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;162;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_storage "/opt/dna/nodus/build/test_storage")
set_tests_properties(test_storage PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;167;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_hashring "/opt/dna/nodus/build/test_hashring")
set_tests_properties(test_hashring PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;172;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_tcp "/opt/dna/nodus/build/test_tcp")
set_tests_properties(test_tcp PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;177;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_tier1 "/opt/dna/nodus/build/test_tier1")
set_tests_properties(test_tier1 PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;182;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_tier2 "/opt/dna/nodus/build/test_tier2")
set_tests_properties(test_tier2 PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;187;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_channel_store "/opt/dna/nodus/build/test_channel_store")
set_tests_properties(test_channel_store PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;192;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_server "/opt/dna/nodus/build/test_server")
set_tests_properties(test_server PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;197;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
add_test(test_client "/opt/dna/nodus/build/test_client")
set_tests_properties(test_client PROPERTIES  _BACKTRACE_TRIPLES "/opt/dna/nodus/CMakeLists.txt;202;add_test;/opt/dna/nodus/CMakeLists.txt;0;")
subdirs("dsa")
subdirs("kem")
