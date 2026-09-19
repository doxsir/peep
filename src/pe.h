#pragma once
#include <cstdint>
#include <vector>

// dos header как в спеке, только нужные поля. порядок важен, читаем тупо побайтово
struct DosHeader {
    uint8_t  magic[2];          // "MZ"
    uint16_t last_page_bytes;
    uint16_t pages;
    uint16_t relocations;
    uint16_t header_paragraphs;
    uint16_t min_alloc;
    uint16_t max_alloc;
    uint16_t initial_ss;
    uint16_t initial_sp;
    uint16_t checksum;
    uint16_t initial_ip;
    uint16_t initial_cs;
    uint16_t reloc_table_offset;
    uint16_t overlay_number;
    uint32_t e_lfanew;          // смещение PE-заголовка
};

DosHeader read_dos_header(const std::vector<uint8_t>& buf);

// coff header идет сразу за PE\0\0 сигнатурой
struct CoffHeader {
    uint16_t machine;            // 0x8664 amd64, 0x14c i386, 0xaa64 arm64
    uint16_t num_sections;
    uint32_t timestamp;          // unix time сборки
    uint32_t symbol_table_ptr;
    uint32_t num_symbols;
    uint16_t optional_header_size;
    uint16_t characteristics;    // битовые флаги: exe/dll/large-address-aware...
};

CoffHeader read_coff_header(const std::vector<uint8_t>& buf, uint32_t pe_offset);
const char* machine_name(uint16_t machine);

// optional header. у pe32 и pe32+ он разной ширины, imagebase скачет
struct OptionalHeader {
    uint16_t magic;              // 0x10b pe32, 0x20b pe32+
    uint8_t  linker_major;
    uint8_t  linker_minor;
    uint32_t size_of_code;
    uint32_t entrypoint;         // rva
    uint64_t imagebase;
    bool is_plus() const { return magic == 0x20b; }
};

// вернёт false если optional header отсутствует
bool read_optional_header(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                          uint16_t coff_optional_size, OptionalHeader& out);

struct SectionHeader {
    char     name[9];            // 8 байт + ноль, имена длиннее 8 байт - позже
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t characteristics;
};

uint32_t read_sections(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                       uint16_t coff_optional_size, uint16_t num_sections,
                       SectionHeader* out, uint32_t max);

// импорты: список dll, у каждой - список функций
struct ImportDll {
    std::vector<char*> names;   // указатели внутрь buf, не владеем
};

// печатает импорты сама, чтобы не тащить промежуточные структуры
// возвращает число dll или -1 если импортов нет
int dump_imports(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                 uint16_t coff_optional_size, bool is_plus);

// экспорты (для dll). печатает сам, возвращает число функций или -1 если экспортов нет
int dump_exports(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                 uint16_t coff_optional_size, bool is_plus);

// смещение, где кончаются секции и начинается overlay (дописанные данные)
uint32_t overlay_offset(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                        uint16_t coff_optional_size, uint16_t num_sections);

// дерево ресурсов: тип -> сколько записей. возвращает число типов или -1
int dump_resources(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                   uint16_t coff_optional_size, uint16_t num_sections, bool is_plus);

// энтропия сырых байт секции (0..8), для поиска упакованных секций
double section_entropy(const std::vector<uint8_t>& buf, uint32_t raw_ptr, uint32_t raw_size);
