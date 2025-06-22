from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps
from conan.tools.scm import Git


class verificaassinaturaRecipe(ConanFile):
    name = "verificaassinatura"
    version = "0.1"
    package_type = "library"

    # Optional metadata
    license = ""
    author = "Marcus Chaves"
    url = "git@github.com:marvsc/VerificaAssinatura.git"
    description = "Verifica integridade da assinatura digital"
    topics = ("", "", "")

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "src/*", "include/*"

    def requirements(self):
        self.requires("openssl/3.5.0")
        self.requires("assinaturadigital/0.1")
        self.requires("poco/1.11.0")

    def config_options(self):
        if self.settings.os == "Windows":
            self.options.rm_safe("fPIC")

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")
        self.options["poco"].enable_data_postgresql = False
        self.options["poco"].enable_data_mysql = False
        self.options["poco"].enable_activerecord = False
        self.options["poco"].enable_activerecord_compiler = False
        self.options["poco"].enable_apacheconnector = False
        self.options["poco"].enable_cppparser = False
        self.options["poco"].enable_data = False
        self.options["poco"].enable_data_odbc = False
        self.options["poco"].enable_data_sqlite = False
        self.options["poco"].enable_encodings = False
        self.options["poco"].enable_fork = False
        self.options["poco"].enable_json = False
        self.options["poco"].enable_jwt = False
        self.options["poco"].enable_mongodb = False
        self.options["poco"].enable_pagecompiler = False
        self.options["poco"].enable_pagecompiler_file2page = False
        self.options["poco"].enable_pdf = False
        self.options["poco"].enable_pocodoc = False
        self.options["poco"].enable_redis = False
        self.options["poco"].enable_sevenzip = False
        self.options["poco"].enable_xml = False
        self.options["poco"].enable_zip = False

    def layout(self):
        cmake_layout(self)
    
    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    def package_info(self):
        self.cpp_info.libs = ["verificaassinatura"]

