/*
 * SignatureRetrieverTest.h
 *
 *  Created on: Mar 15, 2026
 *      Author: marcus
 */

#ifndef TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_SIGNATURERETRIEVERTEST_H_
#define TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_SIGNATURERETRIEVERTEST_H_

#include <OpenSSLUtils.h>

#include <cppunit/TestFixture.h>

#include <cppunit/extensions/HelperMacros.h>

class SignatureRetrieverTest: public CppUnit::TestFixture {
    CPPUNIT_TEST_SUITE(SignatureRetrieverTest);
    CPPUNIT_TEST(teste_verificacao_com_senha_estendido);
    CPPUNIT_TEST_SUITE_END();
public:
    void teste_verificacao_com_senha_estendido();
};

#endif /* TEST_PACKAGE_SRC_UNITTESTS_INCLUDE_SIGNATURERETRIEVERTEST_H_ */
