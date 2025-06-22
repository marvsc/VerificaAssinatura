cmake_minimum_required(VERSION 3.15)
project(PackageTest CXX)


find_package(verificaassinatura CONFIG REQUIRED)

add_executable(example src/example.cpp)
target_link_libraries(example verificaassinatura::verificaassinatura)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/resources/arquivos/signature.p7s
${CMAKE_CURRENT_BINARY_DIR}/signature.p7s
COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/resources/pkcs12/certificado_teste_hub.pfx
${CMAKE_CURRENT_BINARY_DIR}/certificado_teste_hub.pfx
COPYONLY)
