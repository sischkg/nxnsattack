add_library(
  ipv4
  utils.cpp
  logger.cpp
  wireformat.cpp
  readbuffer.cpp
  udpv4client.cpp udpv4server.cpp
  tcpv4client.cpp tcpv4server.cpp )
add_library( threadpool threadpool.cpp )
add_library( dns shufflebytes.cpp dns.cpp domainname.cpp rrgenerator.cpp )
add_library( dnsserver dns_server.cpp )
add_library( zone
             signedauthserver.cpp
             unsignedauthserver.cpp
             auth_server.cpp
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
add_library( tokenizer tokenizer.cpp )

set( CLIENT_LIBRARY
  dns
  ipv4
  boost_chrono
  boost_log_setup
  boost_log
  boost_program_options
  boost_thread
  boost_system
  ${OPENSSL_CRYPTO_LIBRARY} )
set( SERVER_LIBRARY dnsserver threadpool ${CLIENT_LIBRARY} )
set( ZONE_SERVER_LIBRARY zone tokenizer ${YAML_CPP_LIBRARIES} ${OPENSSL_SSL_LIBRARY} ${SERVER_LIBRARY} )

add_executable( nxnsattack    nxnsattack.cpp )

target_link_libraries( nxnsattack ${ZONE_SERVER_LIBRARY} )

