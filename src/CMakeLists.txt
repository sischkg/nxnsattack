add_library(
  libipv4
  utils.cpp
  wireformat.cpp
  ipv4.cpp udpv4.cpp udpv4client.cpp udpv4server.cpp
  tcpv4.cpp tcpv4client.cpp tcpv4server.cpp )
add_library( libdns dns.cpp domainname.cpp )
add_library( libdnsserver  dns_server.cpp )
add_library( libzone auth_server zoneloader.cpp zone.cpp )

add_executable( zone_server      zone_server.cpp )
add_executable( cve-2015-5470    cve-2015-5470.cpp )
add_executable( cve-2015-8000    cve-2015-8000.cpp )
add_executable( cve-2015-8605    cve-2015-8605.cpp )
add_executable( cve-2015-8704    cve-2015-8704.cpp )
add_executable( cve-2015-8705    cve-2015-8705.cpp )
add_executable( cve-2016-2774    cve-2016-2774.cpp )
add_executable( cve-2016-2848    cve-2016-2848.cpp )
add_executable( cve-2016-5426    cve-2016-5426.cpp )
add_executable( cve-2016-7068    cve-2016-7068.cpp )
add_executable( cve-2016-9131    cve-2016-9131.cpp )
add_executable( cve-2017-3137    cve-2017-3137.cpp )
add_executable( cve-2017-3139    cve-2017-3139.cpp )
add_executable( unbound-caps-dos unbound-caps-dos.cpp )
target_link_libraries( zone_server      libzone ${YAML_CPP_LIBRARIES} libdnsserver boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2015-8000    boost_program_options libdnsserver boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2015-8605    boost_program_options libdnsserver boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2015-8704    boost_program_options libdnsserver boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2015-5470    boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2016-5426    boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2016-2848    boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2016-2774    boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2016-9131    libdnsserver boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2017-3137    libdnsserver boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2017-3139    libdnsserver boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( unbound-caps-dos libdnsserver boost_program_options boost_thread boost_system libdns libipv4 crypto )
target_link_libraries( cve-2016-7068    boost_program_options libdns libipv4 crypto)
target_link_libraries( cve-2015-8705    boost_program_options libdns libipv4 crypto )

