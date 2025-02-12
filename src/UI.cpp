// src/UI.cpp
#include "UI.h"
#include <ncurses.h>
#include <chrono>
#include <thread>

UI::UI() : running_(false) {}

UI::~UI() {
    stop();
}

void UI::start() {
    running_ = true;
    uiThread_ = std::thread(&UI::run, this);
}

void UI::stop() {
    running_ = false;
    if (uiThread_.joinable()) {
        uiThread_.join();
    }
}

void UI::addFlaggedPacket(const FlaggedPacket &flaggedPkt) {
    std::lock_guard<std::mutex> lock(dataMutex_);
    flaggedPackets_.push_back(flaggedPkt);
}

void UI::addAnomaly(const Anomaly &anomaly) {
    std::lock_guard<std::mutex> lock(dataMutex_);
    anomalies_.push_back(anomaly);
}

void UI::run() {
    initscr();            // Start ncurses mode
    cbreak();             // Disable line buffering
    noecho();             // Do not echo user input
    nodelay(stdscr, TRUE); // Non-blocking input
    curs_set(FALSE);      // Hide the cursor

    while (running_) {
        refreshDisplay();
        std::this_thread::sleep_for(std::chrono::seconds(1));
        int ch = getch();
        if (ch == 'q' || ch == 'Q') {
            running_ = false;
        }
    }

    endwin();             // End ncurses mode
}

void UI::refreshDisplay() {
    std::lock_guard<std::mutex> lock(dataMutex_);
    clear();

    mvprintw(0, 0, "Real-Time Packet Monitoring Tool (Press 'q' to quit)");
    mvprintw(2, 0, "Flagged Packets:");
    mvprintw(3, 0, "------------------------------------------------------------");

    int row = 4;
    for (const auto &pkt : flaggedPackets_) {
        if (row >= LINES - 2) break;
        mvprintw(row++, 0, "Src: %s:%d | Dest: %s:%d | Sig: %s",
                 pkt.packet.srcIP.c_str(),
                 pkt.packet.srcPort,
                 pkt.packet.destIP.c_str(),
                 pkt.packet.destPort,
                 pkt.matchedSignature.c_str());
    }

    mvprintw(row + 1, 0, "Anomalies Detected:");
    mvprintw(row + 2, 0, "------------------------------------------------------------");
    row += 3;
    for (const auto &anomaly : anomalies_) {
        if (row >= LINES - 1) break;
        mvprintw(row++, 0, "IP: %s | Count: %d", anomaly.ip.c_str(), anomaly.packetCount);
    }

    refresh();
}