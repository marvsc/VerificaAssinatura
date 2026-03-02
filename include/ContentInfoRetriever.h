/*
 * ContentInfoRetriever.h
 *
 *  Created on: 26 de fev. de 2026
 *      Author: marcus.chaves
 */

#ifndef INCLUDE_CONTENTINFORETRIEVER_H_
#define INCLUDE_CONTENTINFORETRIEVER_H_

#include <set>
#include <memory>

#include <openssl/cms.h>

class ContentInfoRetriever {
public:
    ContentInfoRetriever() : file_content_("") {}
    ContentInfoRetriever(std::shared_ptr<CMS_ContentInfo> content_info) :
        content_info_(content_info), file_content_("") {}
    const std::string get_file_content();
    const std::set<std::string> get_signer_names();
    const std::set<std::string> get_signing_times();
private:
    std::shared_ptr<CMS_ContentInfo> content_info_;
    std::string file_content_;
    std::set<std::string> signer_names_;
    std::set<std::string> signing_times_;
    std::set<std::string> hashs_;

    void retrieve_signer_name(X509* certificate);
    void retrieve_signing_time(CMS_SignerInfo* signer_information);
};

#endif /* INCLUDE_CONTENTINFORETRIEVER_H_ */
