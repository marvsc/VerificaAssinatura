/*
 * SignatureRetrieverTest.cpp
 *
 *  Created on: Mar 15, 2026
 *      Author: marcus
 */

#include "../include/SignatureRetrieverTest.h"

#include "SignatureRetriever.h"

#include "../include/VerificaAssinaturaMacros.h"

#include <cstdio>

#define BUFFER_SIZE 256
#define PRINTF_MESSAGE(format, ...) \
    ([&]() { \
            char buffer[BUFFER_SIZE]; \
            std::snprintf(buffer, BUFFER_SIZE, format, ##__VA_ARGS__); \
            return std::string(buffer); \
    }())

CPPUNIT_TEST_SUITE_REGISTRATION(SignatureRetrieverTest);

void SignatureRetrieverTest::teste_verificacao_com_senha_estendido() {
    SignatureRetriever signature_retriever(PKCS12_FILE_PATH,
            OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD),
                    AES_KEY, reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)),
            SIGNATURE_FILE_PATH);
    CPPUNIT_ASSERT_MESSAGE("Erro verificando assinatura digital", signature_retriever.verify());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo nomes de assinantes", !signature_retriever.get_signer_names().empty());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo horario das assinaturas", !signature_retriever.get_signing_times().empty());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo hash", !signature_retriever.get_hash().empty());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo algoritmos de sumário de mensagem", !signature_retriever.get_algorithms().empty());
    CPPUNIT_ASSERT_MESSAGE("Devia haver somente um algoritmo de sumário de mensagem", signature_retriever.get_algorithms().size() == 1);
    CPPUNIT_ASSERT_MESSAGE(PRINTF_MESSAGE("Deveria encontrar o algoritmo %s, mas o algoritmo %s foi encontrado", MESSAGE_DIGEST_ALGORITHM, signature_retriever.get_algorithms().begin()->c_str()), *signature_retriever.get_algorithms().begin() == MESSAGE_DIGEST_ALGORITHM);
}
