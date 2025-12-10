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


#pragma region Helper Functions

/// <summary>
/// Конвертує системний час файлу у читабельний рядок дати.
/// </summary>
/// <param name="ftime">Час останньої зміни файлу (std::filesystem format).</param>
/// <returns>Рядок формату "Www Mmm dd hh:mm:ss yyyy".</returns>
std::string FileTimeToString(fs::file_time_type ftime) {
    // Filesystem clock відрізняється від системного годинника, тому потрібна конвертація
    // для отримання коректної календарної дати.
    auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
        ftime - fs::file_time_type::clock::now() + std::chrono::system_clock::now()
    );
    std::time_t tt = std::chrono::system_clock::to_time_t(sctp);

    char buffer[32];
    ctime_s(buffer, sizeof(buffer), &tt);

    std::string result(buffer);
    // ctime додає символ нового рядка в кінці, який може порушити форматування логів/UI.
    if (!result.empty() && result.back() == '\n') result.pop_back();
    return result;
}

/// <summary>
/// Здійснює запис повідомлень одночасно у консоль та у лог-файл.
/// </summary>
/// <param name="message">Текст повідомлення.</param>
void Log(const std::string& message) {
    // Вивід у консоль безпечний для кирилиці завдяки попередньому виклику SetConsoleOutputCP(1251).
    std::cout << message << std::endl;

    // Відкриваємо файл у режимі додавання (append), щоб зберегти історію попередніх запусків.
    std::ofstream logFile("server_log.txt", std::ios::app);
    if (logFile.is_open()) {
        time_t now = time(0);
        char dt[30];
        ctime_s(dt, sizeof(dt), &now);
        std::string timeStr(dt);
        if (!timeStr.empty()) timeStr.pop_back();

        logFile << "[" << timeStr << "] " << message << "\n";
        logFile.close();
    }
}

/// <summary>
/// Перевіряє відповідність рядка заданій масці (Wildcard matching).
/// Реалізовано вручну, щоб уникнути залежності від специфічних Windows-бібліотек (Shlwapi).
/// </summary>
/// <param name="text">Текст для перевірки (напр. ім'я файлу).</param>
/// <param name="pattern">Маска з підтримкою '*' та '?'.</param>
/// <returns>true, якщо текст відповідає масці.</returns>
bool MatchPattern(const std::string& text, const std::string& pattern) {
    const char* s = text.c_str();
    const char* p = pattern.c_str();
    const char* star = nullptr;
    const char* s_star = nullptr;

    while (*s) {
        // Звичайний збіг символів або одиничний джокер '?'
        if (*p == *s || *p == '?') {
            s++;
            p++;
            continue;
        }
        // Обробка багатосимвольного джокера '*'
        // Запам'ятовуємо позицію зірочки для можливого бектрекінгу (повернення назад)
        if (*p == '*') {
            star = p++;
            s_star = s;
            continue;
        }
        // Якщо символи не збіглися, але була активна зірочка - пробуємо
        // "поглинути" ще один символ тексту зірочкою.
        if (star) {
            p = star + 1;
            s = ++s_star;
            continue;
        }
        return false;
    }

    // Пропускаємо залишкові зірочки в кінці патерну (напр. "file*")
    while (*p == '*') p++;

    return !*p;
}

#pragma endregion

#pragma region Business Logic

/// <summary>
/// Сканує директорію та повертає список файлів, що відповідають фільтру.
/// </summary>
/// <param name="subPath">Відносний шлях всередині ServerRoot.</param>
/// <param name="extFilter">Маска розширення файлів.</param>
/// <returns>Вектор структур з інформацією про файли.</returns>
std::vector<FileInfoPacket> ScanDirectory(const std::string& subPath, const std::string& extFilter) {
    std::vector<FileInfoPacket> results;

    // Використовуємо path::operator/ для коректного формування шляху незалежно від ОС.
    fs::path fullPath = fs::path(ROOT_DIR) / subPath;

    // Перевірка існування директорії перед ітерацією запобігає виняткам fs::directory_iterator.
    if (!fs::exists(fullPath) || !fs::is_directory(fullPath)) {
        Log("[Info] Папка не знайдена: " + fullPath.string());
        return results;
    }

    try {
        for (const auto& entry : fs::directory_iterator(fullPath)) {
            // Обробляємо лише файли, ігноруючи підпапки та символічні посилання.
            if (entry.is_regular_file()) {
                std::string fileName = entry.path().filename().string();

                // Якщо фільтр порожній, застосовуємо дефолтний ("все"), щоб уникнути логічних помилок.
                std::string mask = extFilter.empty() ? "*.*" : extFilter;

                if (MatchPattern(fileName, mask)) {
                    FileInfoPacket packet;

                    // Використовуємо безпечні функції копіювання рядків (strcpy_s) для уникнення buffer overflow.
                    strcpy_s(packet.name, fileName.c_str());
                    strcpy_s(packet.date, FileTimeToString(entry.last_write_time()).c_str());
                    packet.size = static_cast<long>(entry.file_size());

                    results.push_back(packet);
                }
            }
        }
    }
    catch (const std::exception& e) {
        // Перехоплення винятків необхідне, оскільки доступ до файлів може бути обмежений правами ОС.
        Log("[Error] Помилка доступу до файлів: " + std::string(e.what()));
    }

    return results;
}

#pragma endregion