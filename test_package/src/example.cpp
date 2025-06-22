#include <unistd.h>
#include <string>

#include "VerificaAssinatura.h"

int main(const int argc, char *const argv[]) {
    int opt;
    std::string pkcs12_file("");
    std::string password("");
    std::string signature_file("");
    while ((opt = getopt(argc, argv, "p:o:x:")) != -1) {
        switch (opt) {
        case 'x':
            pkcs12_file = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 'o':
            signature_file = optarg;
            break;
        case '?':
            std::printf("Opção inválida: %c\n", opt);
            break;
        default:
            std::printf("Erro no parser: %c\n", opt);
            break;
        }
    }
    if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            std::printf("Argumento inválido: %s\n", argv[i]);
        }
    }
    if (pkcs12_file.empty()) {
        std::printf("Arquivo PKCS12 inválido\n");
        return EXIT_FAILURE;
    }
    if (password.empty()) {
        std::printf("Senha inválida\n");
        return EXIT_FAILURE;
    }
    if (signature_file.empty()) {
        std::printf("Arquivo de assinatura inválido\n");
        return EXIT_FAILURE;
    }
    try {
        VerificaAssinatura va(pkcs12_file, password, signature_file);
        if (va.verify()) {
            std::printf("Arquivo %s de assinatura válido\n", signature_file.c_str());
            std::set<std::string> signer_names = va.get_signer_names();
            for (std::string signer_name : signer_names) {
                std::printf("Nome do signatário encontrado: %s\n", signer_name.c_str());
            }
            std::set<std::string> signing_times = va.get_signing_times();
            for (std::string signing_time : signing_times) {
                std::printf("Data da assinatura encontrada: %s\n", signing_time.c_str());
            }
            std::printf("Hash do documento: %s\n", va.get_file_content().c_str());
        } else {
            va.throw_error("Arquivo %s de assinatura inválido");
        }
    } catch (std::exception& e) {
        std::printf("Erro de execução: %s\n", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
