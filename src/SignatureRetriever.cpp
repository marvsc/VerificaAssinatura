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

#include <Poco/Net/HTTPStreamFactory.h>

SignatureRetriever::SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path) :
        certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free),
        store_(X509_STORE_new(), X509_STORE_free), file_content_hex_(""), hash_("") {
    PKCS12Parser parser(pkcs12_file_path);
    init(cms_file, parser.parse());
}

SignatureRetriever::SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path,
        const std::string& pkcs12_password) :
                certificates_(sk_X509_new_null(), OSSL_STACK_OF_X509_free),
                store_(X509_STORE_new(), X509_STORE_free), file_content_hex_(""), hash_("") {
    PKCS12Parser parser(pkcs12_file_path, pkcs12_password);
    init(cms_file, parser.parse());
}

void SignatureRetriever::init(const std::string& cms_file, const Data::POCO::PKCS12POCO& pkcs12_poco) {
    if (!sk_X509_push(certificates_.get(), pkcs12_poco.certificate.get())) {
        OpenSSLUtils::openssl_error_handling("Erro adicionando certificado a verificação");
    }
    std::unique_ptr<BIO, decltype(&BIO_free)> cms_buffer(BIO_new_file(cms_file.c_str(), "r"), BIO_free);
    content_info_.reset(d2i_CMS_bio(cms_buffer.get(), nullptr));
    std::string url_cacert = get_issuer_uri(pkcs12_poco.certificate);
    std::vector<char> cacert = download_cacert(url_cacert);
    std::shared_ptr<PKCS7> pkcs7 = prepare_pkcs7_structure(cacert);
    X509* certificate_authority = find_certificate_authority(pkcs7->d.sign->cert);
    std::shared_ptr<Poco::TemporaryFile> temporary_certificate = write_certificate_to_temporary_file(certificate_authority);
    load_temporary_certificate(temporary_certificate);
}

bool SignatureRetriever::verify() {
    std::unique_ptr<BIO, decltype(&BIO_free_all)> content_bio(BIO_new(BIO_s_mem()), BIO_free_all);
    if (!CMS_verify(content_info_.get(), certificates_.get(), store_.get(), nullptr, content_bio.get(), 0)) {
        return false;
    }
    BUF_MEM* content_buffer = nullptr;
    BIO_get_mem_ptr(content_bio.get(), &content_buffer);
    file_content_hex_.assign(OPENSSL_buf2hexstr(reinterpret_cast<const unsigned char*>(content_buffer->data),
            content_buffer->length));
    return true;
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

void SignatureRetriever::load_temporary_certificate(std::shared_ptr<Poco::TemporaryFile> temporary_certificate) const {
    if (!X509_STORE_load_locations(store_.get(), temporary_certificate->path().c_str(), nullptr)) {
        OpenSSLUtils::openssl_error_handling("Erro carregando certificado da autoridade certificadora");
    }
}

std::string SignatureRetriever::get_file_content_hex() const {
    if (file_content_hex_.empty()) {
        throw std::runtime_error("Arquivo não verificado");
    }
    return file_content_hex_;
}

std::set<std::string> SignatureRetriever::get_signer_names() const {
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

std::set<std::string> SignatureRetriever::get_signing_times() const {
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

std::string SignatureRetriever::get_hash() const {
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
    // TODO: ARRUMAR
    hash_.assign(reinterpret_cast<char*>((*encap_content)->data));
    return hash_;
}



/*
 * #include <openssl/cms.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>

// Function to print the digest algorithm
void print_encap_digest_alg(CMS_ContentInfo *cms) {
    if (CMS_get0_type(cms) != OBJ_nid2obj(NID_pkcs7_signed)) {
        std::cerr << "Not a SignedData structure" << std::endl;
        return;
    }

    // 1. Get the SignedData structure
    CMS_SignedData *sd = CMS_get0_SignedData(cms);
    if (!sd) return;

    // 2. Get the stack of digest algorithms
    const STACK_OF(X509_ALGOR) *algors = CMS_SignedData_get0_digestAlgs(sd);

    // 3. Iterate through algorithms (usually one)
    for (int i = 0; i < sk_X509_ALGOR_num(algors); i++) {
        X509_ALGOR *alg = sk_X509_ALGOR_value(algors, i);

        // 4. Get the NID (Numerical Identifier) of the algorithm
        ASN1_OBJECT *alg_obj;
        X509_ALGOR_get0(&alg_obj, NULL, NULL, alg);
        int nid = OBJ_obj2nid(alg_obj);

        std::cout << "Digest Algorithm: " << OBJ_nid2ln(nid) << std::endl;
    }
}

// Usage Example (assuming CMS_ContentInfo *cms is loaded)
// print_encap_digest_alg(cms);
 *
 */

