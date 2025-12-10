#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>
#include <Windows.h>

namespace fs = std::filesystem;

#pragma region Configuration

// Порт за замовчуванням для прослуховування вхідних з'єднань.
const char* DEFAULT_PORT = "8080";

// Назва кореневої папки-пісочниці.
// Сервер обмежує доступ до файлової системи лише цією директорією з міркувань безпеки.
const std::string ROOT_DIR = "ServerRoot";

#pragma endregion

#pragma region Protocol Definitions

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

#pragma endregion
