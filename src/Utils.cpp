// src/Utils.cpp
#include "Utils.h"
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <fstream>

std::mutex Utils::logMutex_;

std::string Utils::getCurrentTimestamp() {
    auto now = std::chrono::system_clock::now();
    std::time_t now_time = std::chrono::system_clock::to_time_t(now);
    std::tm *ptm = std::localtime(&now_time);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", ptm);
    return std::string(buffer);
}

void Utils::logEvent(const std::string &event, LogLevel level) {
    std::lock_guard<std::mutex> lock(logMutex_);
    rotateLogs(); // Rotate if needed

    std::ofstream logFile("log.txt", std::ios::app);
    if (logFile.is_open()) {
        std::string levelStr;
        switch (level) {
            case LogLevel::INFO:
                levelStr = "INFO";
                break;
            case LogLevel::WARNING:
                levelStr = "WARNING";
                break;
            case LogLevel::ERROR:
                levelStr = "ERROR";
                break;
        }
        logFile << "[" << getCurrentTimestamp() << "] [" << levelStr << "] " << event << std::endl;
        logFile.close();
    }
}

void Utils::rotateLogs() {
    const std::string logFileName = "log.txt";
    const std::string backupFileName = "log_backup.txt";
    std::ifstream infile(logFileName, std::ios::ate | std::ios::binary);
    if (infile.is_open()) {
        std::streamsize size = infile.tellg();
        infile.close();
        const std::streamsize maxSize = 10 * 1024 * 1024; // 10 MB
        if (size >= maxSize) {
            std::rename(logFileName.c_str(), backupFileName.c_str());
        }
    }
}