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

CI собирает на ubuntu при каждом пуше.

## Что умеет (v0.3)

- DOS header: MZ magic, размеры, начальные регистры, e_lfanew
- COFF header: machine (amd64/i386/arm64...), число секций, timestamp сборки, флаги
- Optional header: PE32/PE32+, версия линкера, entrypoint (rva + абсолютный адрес), imagebase
- Таблица секций: имя, размеры, vaddr, флаги W/X/C
- Import table: все dll и функции, ординалы
- Export table: имена, ординалы, forwarders (rva внутрь директории = строка)
- Overlay: смещение, размер, hex-превью первых байт

## Планы

- resource directory viewer
- PE diff: сравнение двух файлов по заголовкам/секциям/импортам
- entropy по секциям

Учусь по 0xrick lab и ired.team, спека от microsoft лежит в свободном доступе.
