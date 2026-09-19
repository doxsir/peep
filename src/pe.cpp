#include "pe.h"
#include <cstdio>

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

static uint64_t u64(const std::vector<uint8_t>& b, size_t off)
{
    return (uint64_t)u32(b, off) | ((uint64_t)u32(b, off + 4) << 32);
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

bool read_optional_header(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                          uint16_t coff_optional_size, OptionalHeader& out)
{
    if (coff_optional_size == 0)
        return false;  // object files без optional header, это норма

    size_t off = pe_offset + 4 + 20;  // sig + coff
    if (off + 2 > buf.size())
        return false;

    out.magic        = u16(buf, off);
    out.linker_major = buf[off + 2];
    out.linker_minor = buf[off + 3];
    out.size_of_code = u32(buf, off + 4);
    out.entrypoint   = u32(buf, off + 16);  // rva, адрес = imagebase + rva

    if (out.magic == 0x20b)
        out.imagebase = u32(buf, off + 24) | ((uint64_t)u32(buf, off + 28) << 32);
    else if (out.magic == 0x10b)
        out.imagebase = u32(buf, off + 28);
    else
        return false;  // rom image (0x107) не трогаем, маловероятно что встретится

    return true;
}

// секции начинаются сразу после optional header
uint32_t read_sections(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                       uint16_t coff_optional_size, uint16_t num_sections,
                       SectionHeader* out, uint32_t max)
{
    size_t off = pe_offset + 4 + 20 + coff_optional_size;
    uint32_t n = 0;
    for (uint16_t i = 0; i < num_sections && n < max; i++) {
        size_t s = off + (size_t)i * 40;  // каждая запись ровно 40 байт
        if (s + 40 > buf.size())
            break;
        SectionHeader& sec = out[n];
        int j = 0;
        for (; j < 8 && buf[s + j]; j++)
            sec.name[j] = (char)buf[s + j];
        sec.name[j] = 0;
        sec.virtual_size       = u32(buf, s + 8);
        sec.virtual_address    = u32(buf, s + 12);
        sec.size_of_raw_data   = u32(buf, s + 16);
        sec.pointer_to_raw_data = u32(buf, s + 20);
        sec.characteristics    = u32(buf, s + 36);
        n++;
    }
    return n;
}

// rva -> смещение в файле через таблицу секций
static uint32_t rva_to_offset(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                              uint16_t opt_size, uint16_t num_sections, uint32_t rva)
{
    size_t sec_off = pe_offset + 4 + 20 + opt_size;
    for (uint16_t i = 0; i < num_sections; i++) {
        size_t s = sec_off + (size_t)i * 40;
        if (s + 40 > buf.size())
            break;
        uint32_t vaddr = u32(buf, s + 12);
        uint32_t vsize = u32(buf, s + 8);
        uint32_t rawsize = u32(buf, s + 16);
        uint32_t rawptr = u32(buf, s + 20);
        uint32_t span = rawsize > vsize ? rawsize : vsize;  // кто из них больше - загадка
        if (rva >= vaddr && rva < vaddr + span)
            return rva - vaddr + rawptr;
    }
    return 0;
}

static const char* cstr_at(const std::vector<uint8_t>& buf, uint32_t file_off)
{
    if (file_off == 0 || file_off >= buf.size())
        return "";
    return (const char*)&buf[file_off];
}

int dump_imports(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                 uint16_t coff_optional_size, bool is_plus)
{
    size_t opt = pe_offset + 4 + 20;
    size_t dd = opt + (is_plus ? 0x70 : 0x68);  // data directory, entry 1 = imports
    if (dd + 8 > buf.size())
        return -1;
    uint32_t imp_rva = u32(buf, dd);
    if (!imp_rva)
        return -1;

    uint32_t imp_off = rva_to_offset(buf, pe_offset, coff_optional_size,
                                     u16(buf, pe_offset + 6), imp_rva);
    if (!imp_off)
        return -1;

    int dlls = 0;
    for (size_t d = imp_off; dlls < 64; d += 20) {  // 64 dll хватит всем, ну почти
        if (d + 20 > buf.size())
            break;
        uint32_t oft = u32(buf, d);
        uint32_t name_rva = u32(buf, d + 12);
        uint32_t ft = u32(buf, d + 16);
        if (!oft && !ft && !name_rva)
            break;  // нулевой дескриптор = конец таблицы

        printf("  %s\n", cstr_at(buf, rva_to_offset(buf, pe_offset, coff_optional_size,
                                                    u16(buf, pe_offset + 6), name_rva)));
        uint32_t thunk_rva = oft ? oft : ft;
        uint32_t toff = rva_to_offset(buf, pe_offset, coff_optional_size,
                                      u16(buf, pe_offset + 6), thunk_rva);
        size_t tsize = is_plus ? 8 : 4;
        for (size_t t = toff, k = 0; t + tsize <= buf.size(); t += tsize, k++) {
            (void)k;
            uint64_t val = is_plus ? u64(buf, t) : u32(buf, t);
            if (!val)
                break;
            uint64_t ordinal_flag = is_plus ? 0x8000000000000000ULL : 0x80000000ULL;
            if (val & ordinal_flag) {
                printf("      #%u (ordinal)\n", (unsigned)(val & 0xFFFF));
            } else {
                // hint (2 байта) + имя
                uint32_t name_off = rva_to_offset(buf, pe_offset, coff_optional_size,
                                                  u16(buf, pe_offset + 6), (uint32_t)val);
                printf("      %s\n", cstr_at(buf, name_off ? name_off + 2 : 0));
            }
        }
        dlls++;
    }
    return dlls;
}

int dump_exports(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                 uint16_t coff_optional_size, bool is_plus)
{
    (void)is_plus;  // export directory одинаков для pe32/pe32+
    size_t opt = pe_offset + 4 + 20;
    size_t dd = opt + 0x00;  // data directory entry 0 = exports
    if (dd + 8 > buf.size())
        return -1;
    uint32_t dir_rva = u32(buf, dd);
    uint32_t dir_size = u32(buf, dd + 4);
    if (!dir_rva)
        return -1;

    uint16_t num_sections = u16(buf, pe_offset + 6);
    uint32_t dir_off = rva_to_offset(buf, pe_offset, coff_optional_size, num_sections, dir_rva);
    if (!dir_off || dir_off + 40 > buf.size())
        return -1;

    const char* dll_name = cstr_at(buf, rva_to_offset(buf, pe_offset, coff_optional_size,
                                                      num_sections, u32(buf, dir_off + 12)));
    uint32_t base = u32(buf, dir_off + 16);
    uint32_t nfuncs = u32(buf, dir_off + 20);
    uint32_t nnames = u32(buf, dir_off + 24);
    uint32_t funcs_off = rva_to_offset(buf, pe_offset, coff_optional_size, num_sections, u32(buf, dir_off + 28));
    uint32_t names_off = rva_to_offset(buf, pe_offset, coff_optional_size, num_sections, u32(buf, dir_off + 32));
    uint32_t ords_off = rva_to_offset(buf, pe_offset, coff_optional_size, num_sections, u32(buf, dir_off + 36));

    printf("  dll: %s, ordinal base: %u, functions: %u (named: %u)\n",
           dll_name, base, nfuncs, nnames);

    int printed = 0;
    for (uint32_t i = 0; i < nnames && printed < 50; i++, printed++) {
        if (names_off + 4 > buf.size() || ords_off + 2 > buf.size())
            break;
        uint32_t name_rva = u32(buf, names_off + i * 4);
        uint16_t ord_index = u16(buf, ords_off + i * 2);
        uint32_t func_rva = u32(buf, funcs_off + (uint32_t)ord_index * 4);
        const char* marker = "";
        // rva внутрь самой export directory = forwarder, там строка "чужая.dll.функция"
        if (func_rva >= dir_rva && func_rva < dir_rva + dir_size) {
            marker = " (forwarder)";
        }
        printf("    %u: %s%s\n", base + ord_index,
               cstr_at(buf, rva_to_offset(buf, pe_offset, coff_optional_size, num_sections, name_rva)),
               marker);
        if (marker[0])
            printf("        -> %s\n", cstr_at(buf, rva_to_offset(buf, pe_offset, coff_optional_size, num_sections, func_rva)));
    }
    if (nnames > (uint32_t)printed)
        printf("    ... и ещё %u\n", nnames - printed);
    return (int)nfuncs;
}

uint32_t overlay_offset(const std::vector<uint8_t>& buf, uint32_t pe_offset,
                        uint16_t coff_optional_size, uint16_t num_sections)
{
    size_t sec_off = pe_offset + 4 + 20 + coff_optional_size;
    uint32_t end = pe_offset + 4 + 20 + coff_optional_size + (uint32_t)num_sections * 40;
    for (uint16_t i = 0; i < num_sections; i++) {
        size_t s = sec_off + (size_t)i * 40;
        if (s + 40 > buf.size())
            break;
        uint32_t rawptr = u32(buf, s + 20);
        uint32_t rawsize = u32(buf, s + 16);
        if (rawptr + rawsize > end)
            end = rawptr + rawsize;
    }
    return end;
}
