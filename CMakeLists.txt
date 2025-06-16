cmake_minimum_required(VERSION 3.15)
project(verificaassinatura CXX)



add_executable(verificaassinatura src/verificaassinatura.cpp src/main.cpp)



install(TARGETS verificaassinatura DESTINATION "."
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        )
