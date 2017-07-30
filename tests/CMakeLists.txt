add_executable( test-base64       test-base64.cpp )
add_executable( test-hex          test-hex.cpp )
add_executable( test-md5          test-md5.cpp )
add_executable( test-wireformat   test-wireformat.cpp )
add_executable( test-readbuffer   test-readbuffer.cpp )
add_executable( test-hmac-md5     test-hmac-md5.cpp )
add_executable( test-tokenizer    test-tokenizer.cpp )
add_executable( test-domainname   test-domainname.cpp )
add_executable( test-nsec         test-nsec.cpp )
add_executable( test-zone         test-zone.cpp )
add_executable( test-zoneloader   test-zoneloader.cpp )
target_link_libraries(test-base64     libipv4 crypto gtest pthread)
target_link_libraries(test-hex        libipv4 crypto gtest pthread)
target_link_libraries(test-md5        libipv4 crypto gtest pthread)
target_link_libraries(test-tokenizer  libtokenizer gtest pthread)
target_link_libraries(test-wireformat libipv4 crypto gtest pthread)
target_link_libraries(test-readbuffer libipv4 crypto gtest pthread)
target_link_libraries(test-hmac-md5   libipv4 crypto gtest pthread)
target_link_libraries(test-domainname libdns libipv4 crypto gtest pthread)
target_link_libraries(test-nsec       libdns libipv4 crypto gtest pthread)
target_link_libraries(test-zone       libzone libdns libipv4 ${YAML_CPP_LIBRARIES} crypto gtest pthread )
target_link_libraries(test-zoneloader libzone libdns libipv4 ${YAML_CPP_LIBRARIES} crypto gtest pthread )

add_test(
  NAME base64
  COMMAND test-base64
)

add_test(
  NAME hex
  COMMAND test-hex
)

add_test(
  NAME tokenizer
  COMMAND test-tokenizer
)

#add_test(
#  NAME md5
#  COMMAND test-md5
#)

add_test(
  NAME wireformat
  COMMAND test-wireformat
)

add_test(
  NAME readbuffer
  COMMAND test-readbuffer
)

add_test(
  NAME hmac-md5
  COMMAND test-hmac-md5
)

add_test(
  NAME domainname
  COMMAND test-domainname
)

add_test(
  NAME nsec
  COMMAND test-nsec
)

add_test(
  NAME zone
  COMMAND test-zone
)

add_test(
  NAME zoneloader
  COMMAND test-zoneloader
)

