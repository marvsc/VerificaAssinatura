/*
 * @file VerificaAssinaturaMacros.h
 * @brief Macros necessárias para execução de testes
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_VERIFICAASSINATURAMACROS_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_VERIFICAASSINATURAMACROS_H_

#define PKCS12_FILE_PATH "certificado_teste_hub.pfx"
#define AES_KEY "b90XmFVR51L485rxXXCRhupVxva0yDFh"
#define AES_INITIALIZATION_VECTOR "NSVmgGXSm2jRTiyq"
#define PKCS12_ENVVAR_PASSWORD "PKCS12_ENVVAR_PASSWORD"
#define SIGNATURE_FILE_PATH "signature.p7s"
#define MESSAGE_DIGEST_ALGORITHM "sha256"
#define BUFFER_SIZE 256

// Macro para criação de mensagens de erro
#define PRINTF_MESSAGE(format, ...) \
    ([&]() { \
            char buffer[BUFFER_SIZE]; \
            std::snprintf(buffer, BUFFER_SIZE, format, ##__VA_ARGS__); \
            return std::string(buffer); \
    }())


#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_VERIFICAASSINATURAMACROS_H_ */
