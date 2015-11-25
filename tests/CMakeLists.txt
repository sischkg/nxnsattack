add_executable( test-base64       test-base64.cpp )
add_executable( test-md5          test-md5.cpp )
target_link_libraries(test-base64 libipv4 gtest pthread)
target_link_libraries(test-md5    libipv4 crypto gtest pthread)

add_test(
  NAME base64
  COMMAND test-base64
)

add_test(
  NAME md5
  COMMAND test-md5
)

