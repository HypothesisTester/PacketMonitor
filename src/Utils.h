// src/Utils.h
#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <fstream>
#include <mutex>

enum class LogLevel {
    INFO,
    WARNING,
    ERROR
};

class Utils {
public:
    static std::string getCurrentTimestamp();
    static void logEvent(const std::string &event, LogLevel level = LogLevel::INFO);
    static void rotateLogs();

private:
    static std::mutex logMutex_;
};

#endif // UTILS_H