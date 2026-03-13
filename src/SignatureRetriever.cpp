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
#include <Poco/DateTime.h>
#include <Poco/DateTimeParser.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/DateTimeFormat.h>
#include <Poco/URI.h>

#include <Poco/Net/HTTPStreamFactory.h>

SignatureRetriever::SignatureRetriever(const std::string& pkcs12_file_path, const std::string& cms_file) :
        certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free),
        store_(X509_STORE_new(), X509_STORE_free),
        content_info_(nullptr, CMS_ContentInfo_free), hash_("") {
    PKCS12Parser parser(pkcs12_file_path);
    init(std::move(parser.parse()->certificate), cms_file);
}

SignatureRetriever::SignatureRetriever(const std::string& pkcs12_file_path, const std::string& pkcs12_password,
        const std::string& cms_file) :
                certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free),
                store_(X509_STORE_new(), X509_STORE_free),
                content_info_(nullptr, CMS_ContentInfo_free), hash_("") {
    PKCS12Parser parser(pkcs12_file_path, pkcs12_password);
    init(std::move(parser.parse()->certificate), cms_file);
}

void SignatureRetriever::init(std::unique_ptr<X509, decltype(&X509_free)> certificate, const std::string& cms_file) {
    if (!sk_X509_push(certificates_.get(), certificate.get())) {
        OpenSSLUtils::openssl_error_handling("Erro adicionando certificado a verificação");
    }
    std::string url_cacert(get_issuer_uri(certificate.release()));
    std::vector<char> cacert = download_cacert(url_cacert);
    populate_store(pkcs7_buffer_to_structure(cacert));
    X509_VERIFY_PARAM* param = X509_STORE_get0_param(store_.get());
    if (!param) {
        OpenSSLUtils::openssl_error_handling("Erro obtendo parâmetro de verificação");
    }
    if (!X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY)) {
        OpenSSLUtils::openssl_error_handling("Erro definindo propósito como qualquer");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> cms_buffer(BIO_new_file(cms_file.c_str(), "r"), BIO_free);
    content_info_.reset(d2i_CMS_bio(cms_buffer.get(), nullptr));
}

bool SignatureRetriever::verify() {
    std::unique_ptr<BIO, decltype(&BIO_free_all)> content_bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!CMS_verify(content_info_.get(), certificates_.get(), store_.get(), nullptr, content_bio.get(), 0)) {
        return false;
    }
    return true;
}

const std::string SignatureRetriever::get_issuer_uri(const X509* certificate) const {
    X509_EXTENSION *extension = X509_get_ext(certificate, X509_get_ext_by_NID(certificate,
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
        return reinterpret_cast<const char*>(ASN1_STRING_get0_data(uri_str));
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

std::unique_ptr<PKCS7, decltype(&PKCS7_free)> SignatureRetriever::pkcs7_buffer_to_structure(const std::vector<char>& buffer) const {
    std::unique_ptr<BIO, decltype(&BIO_free)> input(BIO_new_mem_buf(buffer.data(), buffer.size()), BIO_free);
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7(d2i_PKCS7_bio(input.get(), nullptr), PKCS7_free);
    if (!pkcs7.get()) {
        OpenSSLUtils::openssl_error_handling("Erro decodificando PKCS7");
    }
    if (!PKCS7_type_is_signed(pkcs7.get())) {
        throw std::runtime_error("PKCS7 não assinado");
    }
    return pkcs7;
}

void SignatureRetriever::populate_store(std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7) {
    STACK_OF(X509)* certificate_chain = pkcs7->d.sign->cert;
    int certificate_chain_size = sk_X509_num(certificate_chain);
    for (int i = 0; i < certificate_chain_size; i++) {
        X509* certificate = sk_X509_value(certificate_chain, i);
        int crit = -1;
        std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> basic_constraints((BASIC_CONSTRAINTS*) X509_get_ext_d2i(certificate,
                NID_basic_constraints, &crit, nullptr), BASIC_CONSTRAINTS_free);
        if (!basic_constraints.get() || !basic_constraints->ca) {
            continue;
        }
        if (!X509_STORE_add_cert(store_.get(), certificate)) {
            OpenSSLUtils::openssl_error_handling("Erro adicionando certificado da autoridade certificadora");
        }
    }
}

std::set<std::string> SignatureRetriever::get_signer_names() {
    if (!content_info_.get()) {
        throw std::runtime_error("Arquivo não verificado");
    }
    if (!signer_names_.empty()) {
        return signer_names_;
    }
    STACK_OF(X509)* signer_certs = CMS_get0_signers(content_info_.get());
    if (!signer_certs) {
        return signer_names_;
    }
    int signer_certs_length = sk_X509_num(signer_certs);
    for (int i = 0; i < signer_certs_length; i++) {
        X509_NAME* subject_name = X509_get_subject_name(sk_X509_value(signer_certs, i));
        int ca_location = X509_NAME_get_index_by_NID(subject_name, NID_commonName, -1);
        if (ca_location < 0) {
            continue;
        }
        X509_NAME_ENTRY* ca_name_entry = X509_NAME_get_entry(subject_name, ca_location);
        if (!ca_name_entry) {
            continue;
        }
        ASN1_STRING* ca_name = X509_NAME_ENTRY_get_data(ca_name_entry);
        if (!ca_name) {
            continue;
        }
        signer_names_.emplace(reinterpret_cast<const char*>(ASN1_STRING_get0_data(ca_name)));
    }
    return signer_names_;
}

std::set<std::string> SignatureRetriever::get_signing_times() {
    if (!content_info_.get()) {
        throw std::runtime_error("Arquivo não verificado");
    }
    if (!signing_times_.empty()) {
        return signing_times_;
    }
    STACK_OF(CMS_SignerInfo)* signer_informations = CMS_get0_SignerInfos(content_info_.get());
    if (!signer_informations) {
        return signing_times_;
    }
    int signer_informations_length = sk_CMS_SignerInfo_num(signer_informations);
    for (int i = 0; i < signer_informations_length; i++) {
        CMS_SignerInfo* signer_information = sk_CMS_SignerInfo_value(signer_informations, i);
        int attribute_index = CMS_signed_get_attr_by_NID(signer_information, NID_pkcs9_signingTime, -1);
        if (attribute_index < 0) {
            continue;
        }
        ASN1_TYPE* type = X509_ATTRIBUTE_get0_type(CMS_signed_get_attr(signer_information, attribute_index), 0);
        if (!type) {
            continue;
        }
        switch (ASN1_TYPE_get(type)) {
        case V_ASN1_GENERALIZEDTIME:
        {
            Poco::DateTime date_time;
            int time_zone;
            std::string generalized_time(reinterpret_cast<const char*>(type->value.generalizedtime->data), type->value.generalizedtime->length);
            Poco::DateTimeParser::parse("%Y%m%d%H%M%S", generalized_time, date_time, time_zone);
            signing_times_.emplace(Poco::DateTimeFormatter::format(date_time, Poco::DateTimeFormat::SORTABLE_FORMAT, time_zone));
            continue;
        }
        case V_ASN1_UTCTIME:
        {
            Poco::DateTime date_time;
            int time_zone;
            std::string utc_time(reinterpret_cast<const char*>(type->value.utctime->data), type->value.utctime->length);
            Poco::DateTimeParser::parse("%y%m%d%H%M%S", utc_time, date_time, time_zone);
            signing_times_.emplace(Poco::DateTimeFormatter::format(date_time, Poco::DateTimeFormat::SORTABLE_FORMAT, time_zone));
            continue;
        }
        }
    }
    return signing_times_;
}

std::string SignatureRetriever::get_hash() {
    if (!content_info_.get()) {
        throw std::runtime_error("Arquivo não verificado");
    }
    if (!hash_.empty()) {
        return hash_;
    }
    ASN1_OCTET_STRING** encap_content = CMS_get0_content(content_info_.get());
    if (encap_content == nullptr || *encap_content == nullptr) {
        return hash_;
    }
    hash_.assign(OPENSSL_buf2hexstr((ASN1_STRING_get0_data(*encap_content)), ASN1_STRING_length(*encap_content)));
    return hash_;
}

std::set<std::string> SignatureRetriever::get_algorithms() {
    if (!content_info_.get()) {
        throw std::runtime_error("Arquivo não verificado");
    }
    if (!algorithms_.empty()) {
        return algorithms_;
    }
    STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(content_info_.get());
    for (int i = 0; i < sk_CMS_SignerInfo_num(signers); i++) {
        CMS_SignerInfo* signer_info = sk_CMS_SignerInfo_value(signers, i);
        X509_ALGOR* algorithm = nullptr;
        CMS_SignerInfo_get0_algs(signer_info, nullptr, nullptr, &algorithm, nullptr);
        if (!algorithm) {
            continue;
        }
        const ASN1_OBJECT* digest_object = nullptr;
        X509_ALGOR_get0(&digest_object, nullptr, nullptr, algorithm);
        algorithms_.emplace(OBJ_nid2ln(OBJ_obj2nid(digest_object)));
    }
    return algorithms_;
}
