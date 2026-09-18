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

    return 0;
}
