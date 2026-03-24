/*
 * @file SignatureRetrieverTest.h
 * @brief Declaração da classe SignatureRetrieverTest
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_SIGNATURERETRIEVERTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_SIGNATURERETRIEVERTEST_H_

#include <OpenSSLUtils.h>

#include <cppunit/TestFixture.h>

#include <cppunit/extensions/HelperMacros.h>

/*
 * @class SignatureRetriverTest
 * @brief Classe de testes unitários para o SignatureRetriever
 */
class SignatureRetrieverTest: public CppUnit::TestFixture {
    // Declaração do suite de testes
    CPPUNIT_TEST_SUITE(SignatureRetrieverTest);
    // Adicionando steps
    CPPUNIT_TEST(teste_verificacao_com_senha_estendido);
    CPPUNIT_TEST_SUITE_END();
public:

    /*
     * @brief Teste de verificação de arquivo assinado utilizando certificado em
     *          arquivo PKCS 12 com senha.
     */
    void teste_verificacao_com_senha_estendido();
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_SIGNATURERETRIEVERTEST_H_ */
