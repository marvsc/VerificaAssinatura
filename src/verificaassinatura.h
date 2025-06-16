#pragma once

#include <vector>
#include <string>


#ifdef _WIN32
  #define VERIFICAASSINATURA_EXPORT __declspec(dllexport)
#else
  #define VERIFICAASSINATURA_EXPORT
#endif

VERIFICAASSINATURA_EXPORT void verificaassinatura();
VERIFICAASSINATURA_EXPORT void verificaassinatura_print_vector(const std::vector<std::string> &strings);
