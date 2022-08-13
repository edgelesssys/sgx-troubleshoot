add_custom_command(
  OUTPUT helloworld_u.h helloworld_u.c helloworld_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/helloworld.edl
  COMMAND
    openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/helloworld.edl
    --search-path ${OE_INCLUDEDIR} --search-path
    ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(testapp_host host.c ${CMAKE_CURRENT_BINARY_DIR}/helloworld_u.c)
target_include_directories(testapp_host PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(testapp_host openenclave::oehost)
