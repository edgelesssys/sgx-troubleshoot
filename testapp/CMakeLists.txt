cmake_minimum_required(VERSION 3.11)
project(testapp)
find_package(OpenEnclave CONFIG REQUIRED)

add_subdirectory(enclave)
add_subdirectory(host)

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave/enclave.signed
  DEPENDS enclave enclave/helloworld.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/helloworld.conf -k private.pem)
add_custom_command(
  OUTPUT enclave/enclave_debug.signed
  DEPENDS enclave enclave/helloworld_debug.conf private.pem
  COMMAND cp $<TARGET_FILE:enclave> $<TARGET_FILE:enclave>_debug
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave>_debug -c
          ${CMAKE_SOURCE_DIR}/enclave/helloworld_debug.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave/enclave.signed enclave/enclave_debug.signed)
