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

CoffHeader read_coff_header(const std::vector<uint8_t>& buf, uint32_t pe_offset)
{
    // PE\0\0 это 4 байта, coff идет сразу после
    size_t off = pe_offset + 4;
    CoffHeader c{};
    c.machine              = u16(buf, off);
    c.num_sections         = u16(buf, off + 2);
    c.timestamp            = u32(buf, off + 4);
    c.symbol_table_ptr     = u32(buf, off + 8);
    c.num_symbols          = u32(buf, off + 12);
    c.optional_header_size = u16(buf, off + 16);
    c.characteristics      = u16(buf, off + 18);
    return c;
}

const char* machine_name(uint16_t machine)
{
    switch (machine) {
        case 0x8664: return "amd64";
        case 0x014c: return "i386";
        case 0xAA64: return "arm64";
        case 0x01c4: return "armv7";
        default: return "unknown";
    }
}
