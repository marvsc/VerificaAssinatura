/*
 * @file SignatureRetriever.h
 * @brief Declaração da classe SignatureRetriever, métodos e atributos.
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef INCLUDE_SIGNATURERETRIEVER_H_
#define INCLUDE_SIGNATURERETRIEVER_H_

#include <set>
#include <string>
#include <vector>
#include <memory>

#include <openssl/cms.h>
#include <openssl/x509.h>

/*
 * @class SignatureRetriever
 * @brief Classe para verificar assinatura digital e extrair informações da assinatura.
 */
class SignatureRetriever {
public:

    /*
     * @brief Constrói a classe sem senha para acesso ao arquivo PKCS 12.
     *
     * @param[in] pkcs12_file_path Path completo para o arquivo PKCS 12.
     * @param[in] cms_file Path completo para o arquivo assinado utilizando algoritmo CMS attached.
     */
    SignatureRetriever(const std::string& pkcs12_file_path, const std::string& cms_file);

    /*
     * @brief Constrói a classe utilizando senha para acesso ao arquivo PKCS 12.
     *
     * @param[in] pkcs12_file_path Path completo para o arquivo PKCS 12.
     * @param[in] pkcs12_password Senha para acesso ao arquvo PKCS 12.
     * @param[in] cms_file Path completo para o arquivo assinado utilizando algoritmo CMS attached.
     */
    SignatureRetriever(const std::string& pkcs12_file_path, const std::string& pkcs12_password, const std::string& cms_file);

    /*
     * @brief Verifica a assinatura do arquivo assinado utilizando algoritmo CMS attached.
     *
     * @return True se o arquivo estiver assinado com as chaves presentes no arquivo PKCS 12.
     */
    bool verify();

    /*
     * @brief Obtém os nomes dos assinantes se o arquivo já foi verificado. Se ainda não foi
     *          verificado, uma exceção é disparada.
     *
     * @return Set com o nome dos assinantes.
     */
    std::set<std::string> get_signer_names();

    /*
     * @brief Obtém as datas e horas de assinatura se o arquivo já foi verificado. Se ainda não
     *          foi, uma exceção é disparada.
     *
     * @return Set com as datas e horas de assinatura.
     */
    std::set<std::string> get_signing_times();

    /*
     * @brief Obtém o hash do conteúdo assinado em formato hexadecimal.
     *
     * @return Hash do conteúdo assinado em formato hexadecimal.
     */
    std::string get_hash();

    /*
     * @brief Obtém os algoritmos de sumário de mensagem utilizados para encriptar o conteúdo
     *          do arquivo assinado.
     *
     * @return Set com o nome dos algoritmos de sumário de mensagem utilizados para encriptar
     *          o conteúdo do arquivo assinado.
     */
    std::set<std::string> get_algorithms();
private:
    std::unique_ptr<STACK_OF(X509), decltype(&OSSL_STACK_OF_X509_free)> certificates_; ///< @brief Cadeia de certificados a serem utilizados na verificação.
    std::unique_ptr<X509_STORE, decltype(&X509_STORE_free)> store_; ///< @brief Armazenamento de certificados da autoridade certificadora.
    std::unique_ptr<CMS_ContentInfo, decltype(&CMS_ContentInfo_free)> content_info_; ///< @brief Informações sobre o conteúdo do arquivo assinado.
    std::set<std::string> signer_names_; ///< @brief Nomes dos assinantes.
    std::set<std::string> signing_times_; ///< @brief Datas e horas de assinaturas.
    std::string hash_; ///< @brief Hash do conteúdo assinado em hexadecimal.
    std::set<std::string> algorithms_; ///< @brief Algoritmos de sumário de mensagens utilizados para encriptar o conteúdo do arquivo assinado.

    /*
     * @brief Inicializa a classe fazendo parse do arquivo PKCS 12, adicionando o certificado
     *          a cadeia de certificados, baixando o certificado da autoridade certificadora e
     *          adicionando ao armazenamento e carregando as informações sobre o conteúdo do
     *          arquivo assinado.
     *
     * @param[in] certificate Certificado a ser utilizado na verificação do arquivo assinado.
     * @param[in] cms_file Path completo para o arquivo assinado utilizando algoritmo CMS attached.
     */
    void init(X509* certificate, const std::string& cms_file);
};

#endif /* INCLUDE_SIGNATURERETRIEVER_H_ */
