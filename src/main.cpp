// peep - pe parser. пока умеет только dos header, дальше больше
#include <cstdio>
#include <cstdint>
#include <ctime>
#include <vector>
#include "pe.h"

int main(int argc, char** argv)
{
    if (argc < 2) {
        printf("usage: peep <file.exe>\n");
        return 1;
    }

    FILE* f = fopen(argv[1], "rb");
    if (!f) {
        printf("can't open %s\n", argv[1]);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(size);
    fread(buf.data(), 1, size, f);
    fclose(f);

    if (size < 64 || buf[0] != 'M' || buf[1] != 'Z') {
        printf("not an MZ executable\n");
        return 1;
    }

    DosHeader dos = read_dos_header(buf);

    printf("== DOS header ==\n");
    printf("magic           : %.2s\n", (const char*)dos.magic);
    printf("bytes on page   : %u\n", dos.last_page_bytes);
    printf("relocations     : %u\n", dos.relocations);
    printf("header size     : %u paragraphs\n", dos.header_paragraphs);
    printf("min alloc       : 0x%04X\n", dos.min_alloc);
    printf("max alloc       : 0x%04X\n", dos.max_alloc);
    printf("initial ss:sp   : 0x%04X:0x%04X\n", dos.initial_ss, dos.initial_sp);
    printf("initial cs:ip   : 0x%04X:0x%04X\n", dos.initial_cs, dos.initial_ip);
    printf("e_lfanew        : 0x%08X\n", dos.e_lfanew);

    // то что дальше по e_lfanew - в следующем коммите
    if (dos.e_lfanew + 4 <= size) {
        printf("\nPE sig at e_lfanew: %.4s\n", (const char*)&buf[dos.e_lfanew]);
    }

    if (dos.e_lfanew + 4 + 20 > size || buf[dos.e_lfanew] != 'P' || buf[dos.e_lfanew + 1] != 'E') {
        printf("no valid PE header after e_lfanew\n");
        return 1;
    }

    CoffHeader coff = read_coff_header(buf, dos.e_lfanew);
    printf("\n== COFF header ==\n");
    printf("machine         : %s (0x%04X)\n", machine_name(coff.machine), coff.machine);
    printf("sections        : %u\n", coff.num_sections);
    printf("built at        : %s", ctime((const time_t*)&coff.timestamp));
    printf("optional header : %u bytes\n", coff.optional_header_size);
    printf("characteristics : 0x%04X%s%s%s\n", coff.characteristics,
           (coff.characteristics & 0x2000) ? " dll" : "",
           (coff.characteristics & 0x0002) ? " exe" : "",
           (coff.characteristics & 0x0020) ? " large-address-aware" : "");

    OptionalHeader opt;
    if (read_optional_header(buf, dos.e_lfanew, coff.optional_header_size, opt)) {
        printf("\n== Optional header ==\n");
        printf("format          : %s\n", opt.is_plus() ? "PE32+ (64-bit)" : "PE32 (32-bit)");
        printf("linker          : %u.%02u\n", opt.linker_major, opt.linker_minor);
        printf("size of code    : %u\n", opt.size_of_code);
        printf("entrypoint      : rva 0x%X -> 0x%llX\n", opt.entrypoint,
               (unsigned long long)(opt.imagebase + opt.entrypoint));
        printf("imagebase       : 0x%llX\n", (unsigned long long)opt.imagebase);
    } else {
        printf("\noptional header: none (object file?)\n");
    }

    SectionHeader secs[16];  // больше 16 секций бывает редко, ну и ладно
    uint32_t nsecs = read_sections(buf, dos.e_lfanew, coff.optional_header_size,
                                   coff.num_sections, secs, 16);
    printf("\n== Sections (%u) ==\n", nsecs);
    printf("%-10s %10s %12s %10s  flags\n", "name", "vsize", "vaddr", "rawsize");
    for (uint32_t i = 0; i < nsecs; i++) {
        char flags[8];
        int fi = 0;
        if (secs[i].characteristics & 0x40000000) flags[fi++] = 'W';
        if (secs[i].characteristics & 0x80000000) flags[fi++] = 'X';
        if (secs[i].characteristics & 0x00000020) flags[fi++] = 'C';
        if (!fi) flags[fi++] = '-';
        flags[fi] = 0;
        printf("%-10s %10u %12X %10u  %s\n", secs[i].name,
               secs[i].virtual_size, secs[i].virtual_address,
               secs[i].size_of_raw_data, flags);
    }

    // импорты — самое вкусное: что файл таскает с собой
    printf("\n== Imports ==\n");
    int dlls = dump_imports(buf, dos.e_lfanew, coff.optional_header_size, opt.is_plus());
    if (dlls == 0)
        printf("  none\n");
    else if (dlls < 0)
        printf("  no import directory\n");

    // экспорты есть только у dll (и у некоторых системных exe)
    int exports = dump_exports(buf, dos.e_lfanew, coff.optional_header_size, opt.is_plus());
    if (exports > 0)
        printf("\n== Exports ==\n");

    // overlay: всё что дописано после последней секции. там живут инсталляторы,
    // подписи и иногда внезапно целые zip-архивы
    uint32_t ooff = overlay_offset(buf, dos.e_lfanew, coff.optional_header_size, coff.num_sections);
    if (ooff && (uint32_t)size > ooff) {
        printf("\n== Overlay ==\n");
        printf("offset: 0x%X, size: %u bytes (%.1f%% of file)\n",
               ooff, (uint32_t)size - ooff, 100.0 * (size - ooff) / size);
        printf("first bytes:");
        for (int i = 0; i < 32 && ooff + i < size; i++)
            printf(" %02X", buf[ooff + i]);
        printf("\n");
    } else {
        printf("\nno overlay\n");
    }

    return 0;
}
