
#include "../include/SignatureRetrieverTest.h"

#include "SignatureRetriever.h"

#include "../include/VerificaAssinaturaMacros.h"

#include <cstdio>

#include <openssl/x509.h>

#include <Poco/Crypto/PKCS12Container.h>

// Tamanho do buffer utilizado na contrução de mensagens de erro.
#define BUFFER_SIZE 256

// Macro para criação de mensagens de erro
#define PRINTF_MESSAGE(format, ...) \
    ([&]() { \
            char buffer[BUFFER_SIZE]; \
            std::snprintf(buffer, BUFFER_SIZE, format, ##__VA_ARGS__); \
            return std::string(buffer); \
    }())

// Registra o suite de testes
CPPUNIT_TEST_SUITE_REGISTRATION(SignatureRetrieverTest);

void SignatureRetrieverTest::teste_verificacao_com_senha_estendido() {
    // Por segurança, a senha não deve ser armazenada em código, então ela é obtida cifrada com
    // algoritmo AES-256-CBC em base 64 através de uma variável de ambiente.
    std::string password(OpenSSLUtils::decrypt_aes_256_cbc(std::getenv(PKCS12_ENVVAR_PASSWORD), AES_KEY,
            reinterpret_cast<const unsigned char*>(AES_INITIALIZATION_VECTOR)));

    // Instancia o recuperador de dados da assinatura passando arquivo PKCS12, senha e arquivo assinado.
    SignatureRetriever signature_retriever(PKCS12_FILE_PATH, password, SIGNATURE_FILE_PATH);
    CPPUNIT_ASSERT_MESSAGE("Nenhum certificado adicionado a cadeia de certificados utilizada na verificação do arquivo assinado",
            sk_X509_num(signature_retriever.certificates_.get()) > 0);

    // Carrega o arquivo PKCS12 para a memória para validação do recuperador de dados da assinatura.
    Poco::Crypto::PKCS12Container container(PKCS12_FILE_PATH, password);
    std::unique_ptr<X509, decltype(&X509_free)> certificate(container.getX509Certificate().dup(),
            X509_free);
    CPPUNIT_ASSERT_MESSAGE(PRINTF_MESSAGE("Certificado contido no arquivo %s não adicionado a cadeia de certificados utilizada na verificação do arquivo assinado",
            PKCS12_FILE_PATH), sk_X509_find(signature_retriever.certificates_.get(),
                    certificate.get()) >= 0);

    // Obtém os certificados de autoridade certificadora adicionados ao armazenamento.
    STACK_OF(X509_OBJECT)* ca_certs = X509_STORE_get0_objects(signature_retriever.store_.get());
    CPPUNIT_ASSERT_MESSAGE("Nenhum certificado da autoridade certificadora armazenado para verificação do arquivo assinado",
            sk_X509_OBJECT_num(ca_certs) > 0);

    // Obtém os parametros do armazenamento.
    X509_VERIFY_PARAM* param = X509_STORE_get0_param(signature_retriever.store_.get());
    CPPUNIT_ASSERT_MESSAGE("O propósito do armazenamento não é qualquer",
            X509_VERIFY_PARAM_get_purpose(param) == X509_PURPOSE_ANY);
    CPPUNIT_ASSERT_MESSAGE("Conteúdo do arquivo assinado indefinido",
            signature_retriever.content_info_.get());
    CPPUNIT_ASSERT_MESSAGE("Erro verificando assinatura digital", signature_retriever.verify());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo nomes de assinantes",
            !signature_retriever.get_signer_names().empty());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo horario das assinaturas",
            !signature_retriever.get_signing_times().empty());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo hash", !signature_retriever.get_hash().empty());
    CPPUNIT_ASSERT_MESSAGE("Erro extraindo algoritmos de sumário de mensagem",
            !signature_retriever.get_algorithms().empty());
    CPPUNIT_ASSERT_MESSAGE("Devia haver somente um algoritmo de sumário de mensagem",
            signature_retriever.get_algorithms().size() == 1);
    CPPUNIT_ASSERT_MESSAGE(PRINTF_MESSAGE("Deveria encontrar o algoritmo %s, mas o algoritmo %s foi encontrado",
            MESSAGE_DIGEST_ALGORITHM, signature_retriever.get_algorithms().begin()->c_str()),
            *signature_retriever.get_algorithms().begin() == MESSAGE_DIGEST_ALGORITHM);
}
