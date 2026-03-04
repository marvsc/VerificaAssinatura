/*
 * SignatureRetriever.cpp
 *
 *  Created on: 26 de fev. de 2026
 *      Author: marcus.chaves
 */

#include "../include/SignatureRetriever.h"

#include <PKCS12Parser.h>
#include <OpenSSLUtils.h>

SignatureRetriever::SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path) :
        certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free), file_content_hex_("") {
    PKCS12Parser parser(pkcs12_file_path);
    init(cms_file, parser.parse());
}

SignatureRetriever::SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path, const std::string& pkcs12_password) :
        certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free), file_content_hex_("") {
    PKCS12Parser parser(pkcs12_file_path, pkcs12_password);
    init(cms_file, parser.parse());
}

void SignatureRetriever::init(const std::string& cms_file, const Data::POCO::PKCS12POCO& pkcs12_poco) {
    if (!sk_X509_push(certificates_.get(), pkcs12_poco.certificate.get())) {
        OpenSSLUtils::openssl_error_handling("Erro adicionando certificado a verificação");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> cms_buffer(BIO_new_file(cms_file.c_str(), "r"), BIO_free);
    content_info_.reset(d2i_CMS_bio(cms_buffer.get(), nullptr), CMS_ContentInfo_free);
}

bool SignatureRetriever::verify() {
    return false;
}

const std::string SignatureRetriever::get_issuer_uri() {
    X509_EXTENSION *extension = X509_get_ext(parser_.get_certificate().get(),
            X509_get_ext_by_NID(parser_.get_certificate().get(),
            NID_info_access, -1));
    if (!extension) {
        throw std::runtime_error(
                "Não foi possível extrair a extensão do certificado X509");
    }
    std::unique_ptr<AUTHORITY_INFO_ACCESS, decltype(&AUTHORITY_INFO_ACCESS_free)> aia(
            (AUTHORITY_INFO_ACCESS*) X509V3_EXT_d2i(extension),
            AUTHORITY_INFO_ACCESS_free);
    if (!aia.get()) {
        throw std::runtime_error(
                "Não foi possível decodificar a extensão do certificado X509");
    }
    int num_aia = sk_ACCESS_DESCRIPTION_num(aia.get());
    for (int i = 0; i < num_aia; i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia.get(), i);
        if (OBJ_obj2nid(ad->method) == NID_ad_ca_issuers) {
            if (ad->location->type == GEN_URI) {
                const ASN1_IA5STRING *uri_str =
                        ad->location->d.uniformResourceIdentifier;
                if (uri_str && ASN1_STRING_length(uri_str) > 0) {
                    return std::string(
                            (const char*) ASN1_STRING_get0_data(uri_str));
                } else {
                    throw std::runtime_error("URI issuer vazio");
                }
            }
        }
    }
    throw std::runtime_error("URI issuer não encontrado");
}
