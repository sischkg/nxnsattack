add_library(
  libipv4
  utils.cpp
  wireformat.cpp
  readbuffer.cpp
  udpv4client.cpp udpv4server.cpp
  tcpv4client.cpp tcpv4server.cpp )
add_library( libdns dns.cpp domainname.cpp rrgenerator.cpp )
add_library( libdnsserver dns_server.cpp )
add_library( libzone
             signedauthserver.cpp
             unsignedauthserver.cpp
             auth_server.cpp
	     shufflebytes.cpp
             abstractzoneimp.cpp
             signedzone.cpp
             signedzoneimp.cpp
             unsignedzone.cpp
             unsignedzoneimp.cpp
             postsignedzone.cpp
             postsignedzoneimp.cpp
             zonesignerimp.cpp
             zonesigner.cpp
             zoneloader.cpp
             zone.cpp
	     nsecdb.cpp
             nsec3db.cpp )
add_library( libtokenizer tokenizer.cpp )

set( CLIENT_LIBRARY boost_program_options boost_thread boost_system libdns libipv4 ${OPENSSL_CRYPTO_LIBRARY} )
set( SERVER_LIBRARY libdnsserver ${CLIENT_LIBRARY} )
set( ZONE_SERVER_LIBRARY libzone libtokenizer ${YAML_CPP_LIBRARIES} ${OPENSSL_SSL_LIBRARY} ${SERVER_LIBRARY} )

add_executable( zone_server    zone_server.cpp )
add_executable( dnssec_server  dnssec_server.cpp )
add_executable( fuzz_server    fuzz_server.cpp )
add_executable( fuzz_client    fuzz_client.cpp )
add_executable( message_parser message_parser.cpp )

target_link_libraries( zone_server    ${ZONE_SERVER_LIBRARY} )
target_link_libraries( dnssec_server  ${ZONE_SERVER_LIBRARY} )
target_link_libraries( fuzz_server    ${ZONE_SERVER_LIBRARY} )
target_link_libraries( fuzz_client    ${CLIENT_LIBRARY} )
target_link_libraries( message_parser ${CLIENT_LIBRARY} )

