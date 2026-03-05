/*
 * SignatureRetriever.cpp
 *
 *  Created on: 26 de fev. de 2026
 *      Author: marcus.chaves
 */

#include "../include/SignatureRetriever.h"

#include <PKCS12Parser.h>
#include <OpenSSLUtils.h>

#include <Poco/URIStreamOpener.h>

#include <Poco/Net/HTTPStreamFactory.h>

SignatureRetriever::SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path) :
        certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free),
        store_(X509_STORE_new(), X509_STORE_free), file_content_hex_("") {
    PKCS12Parser parser(pkcs12_file_path);
    init(cms_file, parser.parse());
}

SignatureRetriever::SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path,
        const std::string& pkcs12_password) :
                certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free),
                store_(X509_STORE_new(), X509_STORE_free), file_content_hex_("") {
    PKCS12Parser parser(pkcs12_file_path, pkcs12_password);
    init(cms_file, parser.parse());
}

void SignatureRetriever::init(const std::string& cms_file, const Data::POCO::PKCS12POCO& pkcs12_poco) {
    if (!sk_X509_push(certificates_.get(), pkcs12_poco.certificate.get())) {
        OpenSSLUtils::openssl_error_handling("Erro adicionando certificado a verificação");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> cms_buffer(BIO_new_file(cms_file.c_str(), "r"), BIO_free);
    content_info_.reset(d2i_CMS_bio(cms_buffer.get(), nullptr));
}

bool SignatureRetriever::verify() {
    return false;
}

const std::string SignatureRetriever::get_issuer_uri(std::shared_ptr<X509> certificate) {
    X509_EXTENSION *extension = X509_get_ext(certificate.get(), X509_get_ext_by_NID(certificate.get(),
            NID_info_access, -1));
    if (!extension) {
        throw std::runtime_error("Não foi possível extrair a extensão do certificado X509");
    }
    std::unique_ptr<AUTHORITY_INFO_ACCESS, decltype(&AUTHORITY_INFO_ACCESS_free)> aia(
            (AUTHORITY_INFO_ACCESS*) X509V3_EXT_d2i(extension), AUTHORITY_INFO_ACCESS_free);
    if (!aia.get()) {
        throw std::runtime_error("Não foi possível decodificar a extensão do certificado X509");
    }
    int num_aia = sk_ACCESS_DESCRIPTION_num(aia.get());
    for (int i = 0; i < num_aia; i++) {
        ACCESS_DESCRIPTION *ad = sk_ACCESS_DESCRIPTION_value(aia.get(), i);
        if (OBJ_obj2nid(ad->method) != NID_ad_ca_issuers || ad->location->type != GEN_URI) {
            continue;
        }
        const ASN1_IA5STRING *uri_str = ad->location->d.uniformResourceIdentifier;
        if (uri_str && ASN1_STRING_length(uri_str) <= 0) {
            throw std::runtime_error("URI issuer vazio");
        }
        return std::string(reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri_str)));
    }
    throw std::runtime_error("URI issuer não encontrado");
}

const std::vector<char> SignatureRetriever::download_cacert(const std::string &url) const {
    Poco::Net::HTTPStreamFactory::registerFactory();
    Poco::URI uri(url);
    std::unique_ptr<std::istream> cacert_stream(Poco::URIStreamOpener::defaultOpener().open(uri));
    std::vector<char> cacert_vector(std::istreambuf_iterator<char>(*cacert_stream.get()),
            std::istreambuf_iterator<char>());
    return cacert_vector;
}

std::shared_ptr<PKCS7> SignatureRetriever::prepare_pkcs7_structure(const std::vector<char>& buffer) const {
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(buffer.data(), buffer.size()), BIO_free);
    std::shared_ptr<PKCS7> pkcs7(d2i_PKCS7_bio(input.get(), nullptr), PKCS7_free);
    if (!pkcs7.get()) {
        OpenSSLUtils::openssl_error_handling("Erro decodificando PKCS7");
    }
    if (!PKCS7_type_is_signed(pkcs7.get())) {
        throw std::runtime_error("PKCS7 não assinado");
    }
    return pkcs7;
}

X509* SignatureRetriever::find_certificate_authority(const STACK_OF(X509)* certificate_chain) const {
    int certificate_chain_size = sk_X509_num(certificate_chain);
    for (int i = 0; i < certificate_chain_size; i++) {
        X509* certificate = sk_X509_value(certificate_chain, i);
        int crit = -1;
        std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> basic_constraints((BASIC_CONSTRAINTS*) X509_get_ext_d2i(certificate,
                NID_basic_constraints, &crit, nullptr), BASIC_CONSTRAINTS_free);
        if (basic_constraints.get() && basic_constraints->ca) {
            return certificate;
        }
    }
    return nullptr;
}

std::shared_ptr<Poco::TemporaryFile> SignatureRetriever::write_certificate_to_temporary_file(const X509* certificate) const {
    std::shared_ptr<Poco::TemporaryFile> temp_file;
    std::unique_ptr<FILE, int (*)(FILE*)> file_ptr(std::fopen(temp_file->path().c_str(), "wb+"), std::fclose);
    if (!file_ptr.get()) {
        std::runtime_error("Não foi possível criar o arquivo temporário com o certificado da autoridade certificadora");
    }
    if (!PEM_write_X509(file_ptr.get(), certificate)) {
        OpenSSLUtils::openssl_error_handling("Erro escrevendo certificado da autoridade certificadora em disco");
    }
    file_ptr.reset();
    return temp_file;
}
