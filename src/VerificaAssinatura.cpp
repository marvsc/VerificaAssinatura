/*
 * VerificaAssinatura.cpp
 *
 *  Created on: 17/06/2025
 *      Author: marcus
 */

#include "VerificaAssinatura.h"

#include <ctime>
#include <memory>
#include <iostream>
#include <stdexcept>
#include <iterator>

#include <openssl/err.h>
#include <openssl/x509v3.h>

#include <Poco/URI.h>
#include <Poco/Path.h>
#include <Poco/DateTime.h>
#include <Poco/Timestamp.h>
#include <Poco/Exception.h>
#include <Poco/StreamCopier.h>
#include <Poco/TemporaryFile.h>
#include <Poco/DateTimeParser.h>
#include <Poco/DateTimeFormat.h>
#include <Poco/DateTimeFormatter.h>
#include <Poco/URIStreamOpener.h>
#include <Poco/Net/HTTPStreamFactory.h>

bool VerificaAssinatura::verify() {
    parser_.parse();
    std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509)*)> certs(
            sk_X509_new_null(), [](STACK_OF(X509) *_certs) {
                sk_X509_pop_free(_certs, X509_free);
            });
    if (!sk_X509_push(certs.get(), parser_.get_certificate().get())) {
        throw_error("Erro adicionando certificado a verificação");
    }
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store(
            X509_STORE_new(), X509_STORE_free);
    extract_x509_cacert_from_pkcs7_buffer_and_load(store.get(),
            download_cacert(get_issuer_uri()));
    X509_VERIFY_PARAM *param = X509_STORE_get0_param(store.get());
    if (!param) {
        throw_error("Erro obtendo parametro de verificação");
    }
    if (!X509_VERIFY_PARAM_set_purpose(param, X509_PURPOSE_ANY)) {
        throw_error("Erro definindo propósito como quelquer");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> cms_buffer(
            BIO_new_file(cms_file_.c_str(), "r"), BIO_free);
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> cms_content_info(
            d2i_CMS_bio(cms_buffer.get(), NULL), CMS_ContentInfo_free);
    std::unique_ptr<BIO, decltype(&BIO_free_all)> content_bio(
            BIO_new(BIO_s_mem()), BIO_free_all);
    if (!CMS_verify(cms_content_info.get(), certs.get(), store.get(), NULL,
            content_bio.get(), 0)) {
        return false;
    }
    BUF_MEM *content_buffer = nullptr;
    BIO_get_mem_ptr(content_bio.get(), &content_buffer);
    file_content_.assign(OPENSSL_buf2hexstr((const unsigned char*) content_buffer->data, content_buffer->length));
    STACK_OF(X509) *signer_certs = CMS_get0_signers(cms_content_info.get());
    if (signer_certs) {
        int signer_certs_length = sk_X509_num(signer_certs);
        for (int i = 0; i < signer_certs_length; i++) {
            signer_names_.insert(
                    retrieve_signer_name(sk_X509_value(signer_certs, i)));
        }
    }
    STACK_OF(CMS_SignerInfo) *signer_informations = CMS_get0_SignerInfos(
            cms_content_info.get());
    if (signer_informations) {
        int signer_informations_length = sk_CMS_SignerInfo_num(
                signer_informations);
        for (int i = 0; i < signer_informations_length; i++) {
            signing_times_.insert(
                    retrieve_signing_time(
                            sk_CMS_SignerInfo_value(signer_informations, i)));
        }
    }
    return true;
}

const std::string VerificaAssinatura::retrieve_signer_name(
        X509 *certificate) const {
    X509_NAME *subject_name = X509_get_subject_name(certificate);
    int ca_location = X509_NAME_get_index_by_NID(subject_name, NID_commonName,
            -1);
    if (ca_location >= 0) {
        X509_NAME_ENTRY *ca_name_entry = X509_NAME_get_entry(subject_name,
                ca_location);
        if (ca_name_entry) {
            ASN1_STRING *ca_name = X509_NAME_ENTRY_get_data(ca_name_entry);
            if (ca_name) {
                return std::string((const char*) ASN1_STRING_get0_data(ca_name));
            }
        }
    }
    return "";
}

const std::string VerificaAssinatura::retrieve_signing_time(
        CMS_SignerInfo *signer_information) const {
    int attribute_index = CMS_signed_get_attr_by_NID(signer_information,
    NID_pkcs9_signingTime, -1);
    if (attribute_index >= 0) {
        X509_ATTRIBUTE *attribute = CMS_signed_get_attr(signer_information,
                attribute_index);
        ASN1_TYPE *type = X509_ATTRIBUTE_get0_type(attribute, 0);
        if (type) {
            switch (ASN1_TYPE_get(type)) {
            case V_ASN1_GENERALIZEDTIME:
            {
                Poco::DateTime date_time;
                int time_zone;
                Poco::DateTimeParser::parse("%Y%m%d%H%M%S",
                        std::string(
                                (const char*) type->value.generalizedtime->data,
                                type->value.generalizedtime->length), date_time,
                        time_zone);
                return Poco::DateTimeFormatter::format(date_time,
                        Poco::DateTimeFormat::SORTABLE_FORMAT, time_zone);
            }
            case V_ASN1_UTCTIME:
            {
                Poco::DateTime date_time;
                int time_zone;
                Poco::DateTimeParser::parse("%y%m%d%H%M%S",
                        std::string((const char*) type->value.utctime->data,
                                type->value.utctime->length), date_time,
                        time_zone);
                return Poco::DateTimeFormatter::format(date_time, Poco::DateTimeFormat::SORTABLE_FORMAT, time_zone);
            }
            }
        }
    }
    return "";
}

void VerificaAssinatura::throw_error(const char *prefix) const {
    ERR_print_errors_cb([](const char *str, std::size_t len, void *u) {
        std::string str_prefix(static_cast<const char*>(u));
        throw std::runtime_error(str_prefix.append(": ").append(str, len));
        return 0;
    }, (void*) prefix);
}

const std::string VerificaAssinatura::get_issuer_uri() {
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

const std::vector<char> VerificaAssinatura::download_cacert(
        const std::string &url) const {
    Poco::Net::HTTPStreamFactory::registerFactory();
    Poco::URI uri(url);
    std::unique_ptr<std::istream> cacert_stream(
            Poco::URIStreamOpener::defaultOpener().open(uri));
    std::vector<char> cacert_vector(
            std::istreambuf_iterator<char>(*cacert_stream.get()),
            std::istreambuf_iterator<char>());
    return cacert_vector;
}

void VerificaAssinatura::extract_x509_cacert_from_pkcs7_buffer_and_load(
        X509_STORE *store, const std::vector<char> buffer) const {
    std::unique_ptr<BIO, decltype(&BIO_free)> input(
            BIO_new_mem_buf(buffer.data(), buffer.size()), BIO_free);
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7(
            d2i_PKCS7_bio(input.get(), nullptr), PKCS7_free);
    if (!pkcs7.get()) {
        throw_error("Erro decodificando PKCS7");
    }
    if (!PKCS7_type_is_signed(pkcs7.get())) {
        throw std::runtime_error(std::string("PKCS7 não assinado"));
    }
    STACK_OF(X509) *certs = pkcs7->d.sign->cert;
    Poco::TemporaryFile temp_file;
    std::unique_ptr<FILE, int (*)(FILE*)> file_ptr(
            std::fopen(temp_file.path().c_str(), "wb+"), std::fclose);
    int num_certs = sk_X509_num(certs);
    for (int i = 0; i < num_certs; i++) {
        X509 *cert = sk_X509_value(certs, i);
        int crit = -1;
        std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> basic_constraints(
                (BASIC_CONSTRAINTS*) X509_get_ext_d2i(cert,
                NID_basic_constraints, &crit, NULL), BASIC_CONSTRAINTS_free);
        if (!basic_constraints.get() || !basic_constraints->ca) {
            continue;
        }
        if (!PEM_write_X509(file_ptr.get(), cert)) {
            throw_error(
                    "Erro escrevendo certificado da autoridade certificadora em disco");
        }
    }
    file_ptr.reset();
    if (!X509_STORE_load_locations(store, temp_file.path().c_str(), NULL)) {
        throw_error("Erro carrgendo certificado da autoridade certificadora");
    }
}

