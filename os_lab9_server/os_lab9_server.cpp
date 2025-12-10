#include <Windows.h>


/// <summary>
/// Структура пакету запиту від Клієнта.
/// Використовує фіксовані масиви char для безпечної бінарної серіалізації (POD-тип).
/// </summary>
struct RequestPacket {
    char path[256];      // Відносний шлях до папки
    char extension[16];  // Маска пошуку (напр. "*.txt")
};

/// <summary>
/// Структура пакету відповіді про файл.
/// </summary>
struct FileInfoPacket {
    char name[256];
    char date[32];
    long size;
};