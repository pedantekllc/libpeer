project(lib)

# CONFIGURE_DEPENDS, because a plain GLOB is evaluated ONCE at configure time
# and never again. Adding a .c and then building against a warm tree — a CI
# runner's, a cross-build slot's, a developer's laptop — recompiles the
# translation unit that CALLS the new code while silently never compiling the
# new file, and surfaces as an undefined reference with nothing in the output
# naming the cause. CONFIGURE_DEPENDS makes the build step re-glob when the
# directory's contents change, which is what makes that unrepresentable.
file(GLOB SRCS CONFIGURE_DEPENDS "*.c")

file(GLOB HEADERS CONFIGURE_DEPENDS "peer.h" "peer_connection.h" "peer_signaling.h")

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

