#include "pe.h"

// читаем little-endian слова руками, потому что alignment-проказы structs нам не друг
static uint16_t u16(const std::vector<uint8_t>& b, size_t off)
{
    return (uint16_t)(b[off] | (b[off + 1] << 8));
}

static uint32_t u32(const std::vector<uint8_t>& b, size_t off)
{
    return (uint32_t)b[off] | ((uint32_t)b[off + 1] << 8) |
           ((uint32_t)b[off + 2] << 16) | ((uint32_t)b[off + 3] << 24);
}

DosHeader read_dos_header(const std::vector<uint8_t>& buf)
{
    DosHeader d{};
    d.magic[0] = buf[0];
    d.magic[1] = buf[1];
    d.last_page_bytes   = u16(buf, 2);
    d.pages             = u16(buf, 4);
    d.relocations       = u16(buf, 6);
    d.header_paragraphs = u16(buf, 8);
    d.min_alloc         = u16(buf, 10);
    d.max_alloc         = u16(buf, 12);
    d.initial_ss        = u16(buf, 14);
    d.initial_sp        = u16(buf, 16);
    d.checksum          = u16(buf, 18);
    d.initial_ip        = u16(buf, 20);
    d.initial_cs        = u16(buf, 22);
    d.reloc_table_offset = u16(buf, 24);
    d.overlay_number    = u16(buf, 26);
    d.e_lfanew          = u32(buf, 0x3C);
    return d;
}
