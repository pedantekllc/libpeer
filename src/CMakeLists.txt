project(lib)

file(GLOB SRCS CONFIGURE_DEPENDS "*.c")

file(GLOB HEADERS "peer.h" "peer_connection.h" "peer_signaling.h" "twcc.h" "twcc_send.h" "pair_info.h")

add_library(peer
  ${SRCS}
  ${HTTP_SOURCES}
  ${MQTT_SOURCES}
  ${MQTT_SERIALIZER_SOURCES}
)

include_directories(peer PUBLIC
  ${HTTP_INCLUDE_PUBLIC_DIRS}
  ${MQTT_INCLUDE_PUBLIC_DIRS}
)

add_dependencies(peer cjson mbedtls usrsctp srtp2)

# The same user-config mbedtls itself is built with (../mbedtls_user_config.h).
# mbedtls emits it as a PUBLIC compile definition on its OWN targets, but
# mbedtls is an ExternalProject here — libpeer compiles against its INSTALLED
# headers, so no target property propagates. Without this, mbedtls has
# DTLS-SRTP and libpeer's own translation units do not: dtls_srtp.c fails to
# find mbedtls_ssl_srtp_profile and the MBEDTLS_TLS_SRTP_* enums. Both sides
# must name the same file.
target_compile_definitions(peer PUBLIC
  MBEDTLS_USER_CONFIG_FILE="${CMAKE_CURRENT_SOURCE_DIR}/../mbedtls_user_config.h")

target_link_libraries(peer ${DEP_LIBS})

set_target_properties(peer PROPERTIES PUBLIC_HEADER "${HEADERS}")

install(TARGETS peer
  LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib/
  PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_PREFIX}/include/
)

