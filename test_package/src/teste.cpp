/*
 * @file teste.cpp
 * @brief Runner de testes unitários
 * @author Marcus Chaves
 * @date 2026-01-27
 */
#include <iostream>

#include <cppunit/CompilerOutputter.h>
#include <cppunit/TestResult.h>
#include <cppunit/TestResultCollector.h>
#include <cppunit/BriefTestProgressListener.h>

#include <cppunit/extensions/TestFactoryRegistry.h>

#include <cppunit/ui/text/TestRunner.h>

int main(const int argc, const char* argv[]) {
    // Instanciando controlador
    CppUnit::TestResult controller;

    // Instanciando coletor de resultado
    CppUnit::TestResultCollector result;
    controller.addListener(&result);

    // Instanciando monitor de progresso
    CppUnit::BriefTestProgressListener progress;
    controller.addListener(&progress);

    // Instanciando runner
    CppUnit::TestRunner runner;
    runner.addTest(CppUnit::TestFactoryRegistry::getRegistry().makeTest());
    runner.run(controller);

    // Instanciando relatório de testes
    CppUnit::CompilerOutputter outputter(&result, std::cerr);
    outputter.write();
    return result.wasSuccessful() ? EXIT_SUCCESS : EXIT_FAILURE;
}


