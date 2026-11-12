# Test helpers. The real checks are the Python differential tests, run through CTest.
add_executable(decode_dump decode_dump.cpp)
target_link_libraries(decode_dump PRIVATE champollion-core)

add_executable(jit_run jit_run.cpp)
target_link_libraries(jit_run PRIVATE champollion-core)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    add_test(NAME decoder_matches_python
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/diff_decoder.py $<TARGET_FILE:decode_dump>)
    add_test(NAME jit_matches_reference
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/diff_jit.py)
    add_test(NAME jit_memory_and_calls_match_reference
             COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/tests/diff_jit_mem.py)
endif()
