/*
 * ContentInfoRetriever.cpp
 *
 *  Created on: 26 de fev. de 2026
 *      Author: marcus.chaves
 */

#include "../include/ContentInfoRetriever.h"

#include <stdexcept>

const std::string ContentInfoRetriever::get_file_content() {
    if (content_info_.get() == nullptr) {
        throw std::runtime_error("Conteúde de arquivo não verificado.");
    }
    if (!file_content_.empty()) {
        return file_content_;
    }
    std::unique_ptr<BIO, decltype(&BIO_free_all)> content_bio(BIO_new(BIO_s_mem()), BIO_free_all);

}
