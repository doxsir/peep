// peep - pe parser. пока умеет только dos header, дальше больше
#include <cstdio>
#include <cstdint>
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

    return 0;
}
