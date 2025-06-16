#include "verificaassinatura.h"
#include <vector>
#include <string>

int main() {
    verificaassinatura();

    std::vector<std::string> vec;
    vec.push_back("test_package");

    verificaassinatura_print_vector(vec);
}
