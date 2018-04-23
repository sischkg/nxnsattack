

set( TEST_LIBRARY      gtest pthread )
set( UTIL_LIBRARY      libipv4 ${OPENSSL_CRYPTO_LIBRARY} ${TEST_LIBRARY} )
set( DNS_LIBRARY       libdns ${UTIL_LIBRARY} )
set( ZONE_LIBRARY      libzone libtokenizer ${YAML_CPP_LIBRARIES} ${OPENSSL_SSL_LIBRARY} ${DNS_LIBRARY} )

add_executable( test-base64       test-base64.cpp )
add_executable( test-base32       test-base32.cpp )
add_executable( test-hex          test-hex.cpp )
add_executable( test-wireformat   test-wireformat.cpp )
add_executable( test-readbuffer   test-readbuffer.cpp )
add_executable( test-hmac-md5     test-hmac-md5.cpp )
add_executable( test-tokenizer    test-tokenizer.cpp )
add_executable( test-domainname   test-domainname.cpp )
add_executable( test-compression  test-compression.cpp )
add_executable( test-nsec         test-nsec.cpp )
add_executable( test-nsecdb       test-nsecdb.cpp )
add_executable( test-zone         test-zone.cpp )
add_executable( test-zoneloader   test-zoneloader.cpp )
add_executable( test-dnskey       test-dnskey.cpp )
target_link_libraries(test-base64      ${UTIL_LIBRARY} )
target_link_libraries(test-base32      ${UTIL_LIBRARY} )
target_link_libraries(test-hex         ${UTIL_LIBRARY} )
target_link_libraries(test-tokenizer   ${ZONE_LIBRARY} )
target_link_libraries(test-wireformat  ${UTIL_LIBRARY} )
target_link_libraries(test-readbuffer  ${UTIL_LIBRARY} )
target_link_libraries(test-hmac-md5    ${UTIL_LIBRARY} )
target_link_libraries(test-domainname  ${DNS_LIBRARY} )
target_link_libraries(test-compression ${DNS_LIBRARY} )
target_link_libraries(test-nsec        ${DNS_LIBRARY} )
target_link_libraries(test-nsecdb      ${ZONE_LIBRARY} )
target_link_libraries(test-zone        ${ZONE_LIBRARY} )
target_link_libraries(test-zoneloader  ${ZONE_LIBRARY} )
target_link_libraries(test-dnskey      ${ZONE_LIBRARY} )

add_test(
  NAME base64
  COMMAND test-base64
)

add_test(
  NAME base32
  COMMAND test-base32
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
  NAME compression
  COMMAND test-compression
)

add_test(
  NAME nsec
  COMMAND test-nsec
)

add_test(
  NAME nsecdb
  COMMAND test-nsecdb
)

add_test(
  NAME zone
  COMMAND test-zone
)

add_test(
  NAME zoneloader
  COMMAND test-zoneloader
  )

add_test(
  NAME dnskey
  COMMAND test-dnskey
)

