/*
 * SignatureRetriever.cpp
 *
 *  Created on: 26 de fev. de 2026
 *      Author: marcus.chaves
 */

#include "../include/SignatureRetriever.h"

#include <PKCS12Parser.h>

SignatureRetriever::SignatureRetriever(const std::string& pkcs12_file_path) :
        certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free), cms_file_(""), file_content_hex_("") {
    PKCS12Parser parser(pkcs12_file_path);
    init(parser.parse());
}

SignatureRetriever::SignatureRetriever(const std::string& pkcs12_file_path, const std::string& pkcs12_password) :
        cms_file_(""), file_content_hex_("") {
    PKCS12Parser parser(pkcs12_file_path, pkcs12_password);
    init(parser.parse());
}

void SignatureRetriever::init(const Data::POCO::PKCS12POCO& pkcs12_poco) {
    certificates
}
