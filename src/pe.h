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
