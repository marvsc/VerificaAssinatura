# 🔏 VerificaAssinatura

> Biblioteca para verifica assinatura de arquivo assinado utilizando algoritmo CMS attached.

## 📋 Tabela de Conteúdos
- [Sobre](#-sobre)
- [Funcionalidades](#-funcionalidades)
- [Pré-requisitos gerais](#%EF%B8%8F-pr%C3%A9-requisitos-gerais)
- [Instalação](#-instalação)
    - [Pacote](#-Pacote)
    - [CMake](#-cmake)
    - [Conan](#-conan)
        - [Pré-requisitos](#%EF%B8%8F-pr%C3%A9-requisitos)
        - [Passos para a compilação](#-passos-para-a-compilação)
- [Pipeline](#-pipeline)
- [Como Usar](#-como-usar)

## 📖 Sobre

Faz a verificação de arquivo assinado utilizando algoritmo CMS attached e extrai nomes de assinantes, datas de assinatura, hash do conteúdo em hexadecimal e nome dos algoritmos de sumário de mensagem utilizados para cifrar o conteúdo.

## ✨ Funcionalidades

- [x] Verificação da assinatura digital de arquivo assinado utilizando algoritmo CMS attached
- [x] Extrai nomes de assinantes
- [x] Extrai datas de assinatura
- [x] Extrai hash do conteúdo em hexadecimal
- [x] Extrai nome dos algoritmos de sumário de mensagem utilizados para cifrar o conteúdo

## 🛠️ Pré-requisitos gerais

* C++17 ou superior.

## 🚀 Instalação

### 📦 Pacote
1. Baixar o pacote:

    ```bash
    wget https://github.com/marvsc/VerificaAssinatura/releases/download/v<versão>/libverificaassinatura-v<versão>.tgz
    ```

2. Descompactar:

    ```bash
    tar zxvf libverificaassinatura-v<versão>.tgz -C <diretório a descompactar>
    ```

### 🛆 CMake

1. Clonar o projeto:

    ```bash
    git clone git@github.com:marvsc/VerificaAssinatura.git
    ```

2. Criar o diretório build:

    ```bash
    mkdir build
    ```

3. Instalar os geradores:

    ```bash
    conan install . --build=missing
    ```

4. Gerar Makefile:

    ```bash
    cmake -DCMAKE_TOOLCHAIN_FILE=build/Release/generators/conan_toolchain.cmake -S . -B build
    ```

5. Compilar projeto:

    ```bash
    make -C build/
    ```

> [!NOTE]
> O comando acima irá compilar o projeto e gerar o artefato build/libverificaassinatura.a

### 💪🏻 Conan

#### 🛠️ Pré-requisitos

* Conan na versão 2.25.2

#### 👣 Passos para a compilação

1. Clonar o projeto:

    ```bash
    git clone git@github.com:marvsc/VerificaAssinatura.git
    ```

2. Definir a senha de acesso ao arquivo PKCS 12 na variável de ambiente PKCS12_ENVVAR_PASSWORD:

    2.1. Converter a chave e o vetor de inicialização em formato hexadecimal

    ```bash
    echo -n "<chave>" | xxd -p -c 256
    echo -n "<iv> | xxd -p -c 256
    ```

    2.2. Encriptar a senha passando a chave e o vetor de inicialização em hexadecimal

    ```bash
    echo -n "<senha>" | openssl enc -aes-256-cbc -e -base64 -K <chave_hex> -iv <iv_hex>
    ```

    2.3. Definir a variável de ambiente PKCS12_ENVVAR_PASSWORD com a senha encriptada:

    ```bash
    export PKCS12_ENVVAR_PASSWORD=<senha_enc>
    ```

> [!NOTE]
> A chave e o vetor de inicialização podem ser obtidos no arquivo test_package/src/UnitTests/include/VerificaAssinaturaMacros.h

3. Criar o projeto utilizando conan:

    ```bash
    conan create . --build=missing
    ```

> [!NOTE]
> O comando acima vai baixar e compilar todas as dependencias, compilar o projeto e executar os testes que são compostos de 2 executáveis. Um faz os testes unitários e o outro realiza a verifica a assinatura digital do arquivo test_package/resources/arquivos/sinature.p7s e extrai os nomes dos assinantes, datas e horas de assinatura, hash do arquivo em hexadecimal e nomes dos algoritmos de sumário de mensagens utilizados para cifrar o conteúdo. A verificação é feita utilizando o certificado contido no arquivo PKCS 12 test_package/resources/pkcs12/certificado_teste_hub.pfx.

## 🔩 Pipeline
Ao criar uma tag, duas pipelines são disparadas via github para gerar a release automaticamente e para publicar o pacote no repositório do conan (cloudsmith).

## ✅ Como usar

Adicionar a lib ao programa durante a compilação com o comando -lverificaassinatura.
