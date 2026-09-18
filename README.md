# peep

PE (Portable Executable) парсер на чистом C++17. Читает заголовки exe/dll прямо
из байтов, без сторонних библиотек. Пишу его чтобы разобраться в формате, а не
потому что pefile мало.

Название — PE Explorer, ну или просто peep.

## Сборка

```bash
cmake -B build
cmake --build build
./build/peep C:/Windows/System32/notepad.exe
```

## Что умеет (v0.1)

- DOS header: MZ magic, размеры, начальные регистры, e_lfanew
- PE signature check по e_lfanew

## Планы

- COFF header (machine, секции, timestamp)
- Optional header (32/64, entrypoint, imagebase)
- таблица секций с флагами
- import table (что за dll таскает с собой)

Учусь по 0xrick lab и ired.team, спека от microsoft лежит в свободном доступе.
