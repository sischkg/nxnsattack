add_executable( test-base64       test-base64.cpp )
add_executable( test-md5          test-md5.cpp )
add_executable( test-wireformat   test-wireformat.cpp )
add_executable( test-hmac-md5     test-hmac-md5.cpp )
add_executable( test-domainname   test-domainname.cpp )
target_link_libraries(test-base64     libipv4 crypto gtest pthread)
target_link_libraries(test-md5        libipv4 crypto gtest pthread)
target_link_libraries(test-wireformat libipv4 crypto gtest pthread)
target_link_libraries(test-hmac-md5   libipv4 crypto gtest pthread)
target_link_libraries(test-domainname libdns libipv4 crypto gtest pthread)

add_test(
  NAME base64
  COMMAND test-base64
)

add_test(
  NAME md5
  COMMAND test-md5
)

add_test(
  NAME wire-format
  COMMAND test-wireformat
)

add_test(
  NAME hmac-md5
  COMMAND test-hmac-md5
)

add_test(
  NAME domainname
  COMMAND test-domainname
)

