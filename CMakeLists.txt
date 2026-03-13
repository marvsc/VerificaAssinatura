cmake_minimum_required(VERSION 3.15)
project(verificaassinatura CXX)

find_package(assinaturadigital REQUIRED)

add_library(verificaassinatura src/SignatureRetriever.cpp)
target_include_directories(verificaassinatura PUBLIC include)

target_link_libraries(verificaassinatura assinaturadigital::assinaturadigital)

set_target_properties(verificaassinatura PROPERTIES PUBLIC_HEADER "include/SignatureRetriever.h")
install(TARGETS verificaassinatura)
