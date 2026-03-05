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
    SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path);
    SignatureRetriever(const std::string& cms_file, const std::string& pkcs12_file_path, const std::string& pkcs12_password);
    bool verify();
private:
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> content_info_;
    std::unique_ptr<STACK_OF(X509), decltype(&OSSL_STACK_OF_X509_free)> certificates_;
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store_;
    std::string file_content_hex_;
    std::set<std::string> signer_names_;
    std::set<std::string> signing_names_;
    std::set<std::string> hashs_;

    void init(const std::string& cms_file, const Data::POCO::PKCS12POCO& pkcs12_poco);
    const std::string get_issuer_uri(std::shared_ptr<X509> certificate);
    const std::vector<char> download_cacert(const std::string &url) const;
    std::shared_ptr<PKCS7> prepare_pkcs7_structure(const std::vector<char>& buffer) const;
    X509* find_certificate_authority(const STACK_OF(X509)* certificate_chain) const;
    std::shared_ptr<Poco::TemporaryFile> write_certificate_to_temporary_file(const X509* certificate) const;
};

#endif /* INCLUDE_SIGNATURERETRIEVER_H_ */
