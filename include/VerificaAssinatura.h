/*
 * VerificaAssinatura.h
 *
 *  Created on: 17/06/2025
 *      Author: marcus
 */

#ifndef INCLUDE_VERIFICAASSINATURA_H_
#define INCLUDE_VERIFICAASSINATURA_H_

#include <PKCS12Parser.h>

#include <set>
#include <string>
#include <vector>

#include <openssl/cms.h>

class VerificaAssinatura {
public:
    VerificaAssinatura(const std::string &pkcs12_file_path,
            const std::string &password, const std::string &cms_file) :
            parser_(pkcs12_file_path, password), cms_file_(cms_file), file_content_("") {
    }
    virtual ~VerificaAssinatura() {
    }
    const std::string get_file_content() const {
        return file_content_;
    }
    const std::set<std::string> get_signer_names() const {
        return signer_names_;
    }
    const std::set<std::string> get_signing_times() const {
        return signing_times_;
    }
    bool verify();
    void throw_error(const char* prefix) const;
private:
    PKCS12Parser parser_;
    std::string cms_file_;
    std::string file_content_;
    std::set<std::string> signer_names_;
    std::set<std::string> signing_times_;
    std::set<std::string> hashs_;

    const std::string get_issuer_uri();
    const std::vector<char> download_cacert(const std::string &url) const;
    void extract_x509_cacert_from_pkcs7_buffer_and_load(X509_STORE* store, const std::vector<char> pkcs7) const;
    const std::string retrieve_signer_name(X509* certificate) const;
    const std::string retrieve_signing_time(CMS_SignerInfo* signer_information) const;
};

#endif /* INCLUDE_VERIFICAASSINATURA_H_ */
