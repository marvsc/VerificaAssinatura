cmake_minimum_required(VERSION 3.15)
project(PackageTest CXX)


find_package(verificaassinatura CONFIG REQUIRED)
find_package(OpenSSL CONFIG REQUIRED)
find_package(cppunit CONFIG REQUIRED)
find_package(Poco CONFIG REQUIRED)

add_executable(example src/example.cpp)
target_link_libraries(example poco::poco openssl::openssl verificaassinatura::verificaassinatura)

add_executable(teste src/teste.cpp
                    src/UnitTests/src/SignatureRetrieverTest.cpp)
target_link_libraries(teste poco::poco openssl::openssl verificaassinatura::verificaassinatura cppunit::cppunit)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/resources/arquivos/signature.p7s
${CMAKE_CURRENT_BINARY_DIR}/signature.p7s
COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/resources/pkcs12/certificado_teste_hub.pfx
${CMAKE_CURRENT_BINARY_DIR}/certificado_teste_hub.pfx
COPYONLY)
