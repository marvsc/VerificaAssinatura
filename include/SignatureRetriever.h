/*
 * SignatureRetriever.h
 *
 *  Created on: 26 de fev. de 2026
 *      Author: marcus.chaves
 */

#ifndef INCLUDE_SIGNATURERETRIEVER_H_
#define INCLUDE_SIGNATURERETRIEVER_H_

#include <set>
#include <string>
#include <vector>
#include <memory>

#include <openssl/cms.h>
#include <openssl/x509.h>
#include <Poco/TemporaryFile.h>

#include <Data/POCO/PKCS12POCO.h>

class SignatureRetriever {
public:
    SignatureRetriever(const std::string& pkcs12_file_path, const std::string& cms_file);
    SignatureRetriever(const std::string& pkcs12_file_path, const std::string& pkcs12_password, const std::string& cms_file);
    bool verify();
    std::set<std::string> get_signer_names();
    std::set<std::string> get_signing_times();
    std::string get_hash();
    std::set<std::string> get_algorithms();
private:
    std::unique_ptr<STACK_OF(X509), decltype(&OSSL_STACK_OF_X509_free)> certificates_;
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store_;
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> content_info_;
    std::set<std::string> signer_names_;
    std::set<std::string> signing_times_;
    std::string hash_;
    std::set<std::string> algorithms_;

    void init(std::unique_ptr<X509, decltype(&X509_free)> certificate, const std::string& cms_file);
    const std::string get_issuer_uri(const X509* certificate) const;
    const std::vector<char> download_cacert(const std::string &url) const;
    std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7_buffer_to_structure(const std::vector<char>& buffer) const;
    void populate_store(std::unique_ptr<PKCS7, decltype(&PKCS7_free)> pkcs7);
};

#endif /* INCLUDE_SIGNATURERETRIEVER_H_ */
