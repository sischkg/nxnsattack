add_library(
  libipv4
  utils.cpp
  wireformat.cpp
  readbuffer.cpp
  ipv4.cpp udpv4.cpp udpv4client.cpp udpv4server.cpp
  tcpv4.cpp tcpv4client.cpp tcpv4server.cpp )
add_library( libdns dns.cpp domainname.cpp rrgenerator.cpp )
add_library( libdnsserver dns_server.cpp )
add_library( libzone
             signedauthserver.cpp
             craftedsignedauthserver.cpp
             unsignedauthserver.cpp
             auth_server.cpp
	     shufflebytes.cpp
             signedzone.cpp
             signedzoneimp.cpp
             unsignedzone.cpp
             unsignedzoneimp.cpp
             zonesignerimp.cpp
             zonesigner.cpp
             zoneloader.cpp
             zone.cpp
             tokenizer )
add_library( libtokenizer tokenizer.cpp )

set( CLIENT_LIBRARY boost_program_options boost_thread boost_system libdns libipv4 ${OPENSSL_CRYPTO_LIBRARY} )
set( SERVER_LIBRARY libdnsserver ${CLIENT_LIBRARY} )
set( ZONE_SERVER_LIBRARY libzone ${YAML_CPP_LIBRARIES} ${OPENSSL_SSL_LIBRARY} ${SERVER_LIBRARY} )

add_executable( zone_server       zone_server.cpp )
add_executable( cve-2015-5470     cve-2015-5470.cpp )
add_executable( cve-2015-8000     cve-2015-8000.cpp )
add_executable( cve-2015-8605     cve-2015-8605.cpp )
add_executable( cve-2015-8704     cve-2015-8704.cpp )
add_executable( cve-2015-8705     cve-2015-8705.cpp )
add_executable( cve-2016-2774     cve-2016-2774.cpp )
add_executable( cve-2016-2848     cve-2016-2848.cpp )
add_executable( cve-2016-5426     cve-2016-5426.cpp )
add_executable( cve-2016-9131     cve-2016-9131.cpp )
add_executable( cve-2017-3137     cve-2017-3137.cpp )
add_executable( cve-2017-3139     cve-2017-3139.cpp )
add_executable( dnssec_server     dnssec_server.cpp )
add_executable( fuzz_server       fuzz_server.cpp )
add_executable( fuzz_client       fuzz_client.cpp )
add_executable( cve-2017-15120    cve-2017-15120.cpp )
add_executable( nsec_client     nsec_client.cpp )
add_executable( huge_nsec_response huge_nsec_response.cpp )
add_executable( dup_nsec_response dup_nsec_response.cpp )
add_executable( nsec_axfr_server  nsec_axfr_server.cpp )

target_link_libraries( zone_server       ${ZONE_SERVER_LIBRARY} )
target_link_libraries( cve-2015-8000     ${SERVER_LIBRARY} )
target_link_libraries( cve-2015-8605     ${SERVER_LIBRARY} )
target_link_libraries( cve-2015-8704     ${SERVER_LIBRARY} )
target_link_libraries( cve-2015-5470     ${CLIENT_LIBRARY} )
target_link_libraries( cve-2016-5426     ${CLIENT_LIBRARY} )
target_link_libraries( cve-2016-2848     ${CLIENT_LIBRARY} )
target_link_libraries( cve-2016-2774     ${CLIENT_LIBRARY} )
target_link_libraries( cve-2016-9131     ${SERVER_LIBRARY} )
target_link_libraries( cve-2017-3137     ${SERVER_LIBRARY} )
target_link_libraries( cve-2017-3139     ${ZONE_SERVER_LIBRARY} )
target_link_libraries( dnssec_server     ${ZONE_SERVER_LIBRARY} )
target_link_libraries( fuzz_server       ${ZONE_SERVER_LIBRARY} )
target_link_libraries( fuzz_client       ${CLIENT_LIBRARY} )
target_link_libraries( cve-2017-15120    ${SERVER_LIBRARY} )
target_link_libraries( cve-2015-8705     ${CLIENT_LIBRARY} )
target_link_libraries( nsec_client       ${CLIENT_LIBRARY} )
target_link_libraries( huge_nsec_response ${ZONE_SERVER_LIBRARY} )
target_link_libraries( dup_nsec_response ${ZONE_SERVER_LIBRARY} )
target_link_libraries( nsec_axfr_server  ${ZONE_SERVER_LIBRARY} )

