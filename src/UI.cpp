// src/UI.cpp
#include "UI.h"
#include <ncurses.h>
#include <chrono>
#include <thread>

// Constructor
UI::UI() : running_(false) {}

// Destructor
UI::~UI() {
    stop();
}

// Start the UI thread
void UI::start() {
    running_ = true;
    uiThread_ = std::thread(&UI::run, this);
}

// Stop the UI thread and join it
void UI::stop() {
    running_ = false;
    if (uiThread_.joinable()) {
        uiThread_.join();
    }
}

// Add a flagged packet to the display list (thread-safe)
void UI::addFlaggedPacket(const FlaggedPacket &flaggedPkt) {
    std::lock_guard<std::mutex> lock(dataMutex_);
    flaggedPackets_.push_back(flaggedPkt);
}

// Add an anomaly to the display list (thread-safe)
void UI::addAnomaly(const Anomaly &anomaly) {
    std::lock_guard<std::mutex> lock(dataMutex_);
    anomalies_.push_back(anomaly);
}

// Main UI loop
void UI::run() {
    initscr();               // Start ncurses mode
    cbreak();                // Disable line buffering
    noecho();                // Do not echo input characters
    nodelay(stdscr, TRUE);   // Non-blocking input
    curs_set(FALSE);         // Hide the cursor

    while (running_) {
        refreshDisplay();    // Update the display
        
        // Sleep for 200 milliseconds for responsiveness
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        
        int ch = getch();    // Get a key press (or ERR if none)
        if (ch != ERR) {
            // Debug: Print the key code at the bottom of the screen
            mvprintw(LINES - 1, 0, "Key pressed: %d   ", ch);
            refresh();
            
            // Check if the key pressed is 'q' or 'Q'
            if (ch == 'q' || ch == 'Q') {
                running_ = false;
            }
        }
    }
    
    endwin();                // End ncurses mode
}

// Refresh the display with current flagged packets and anomalies
void UI::refreshDisplay() {
    std::lock_guard<std::mutex> lock(dataMutex_);
    clear();
    
    mvprintw(0, 0, "Real-Time Packet Monitoring Tool (Press 'q' to quit)");
    mvprintw(2, 0, "Flagged Packets:");
    mvprintw(3, 0, "------------------------------------------------------------");
    
    int row = 4;
    for (const auto &pkt : flaggedPackets_) {
        if (row >= LINES - 2)
            break;
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
        if (row >= LINES - 1)
            break;
        mvprintw(row++, 0, "IP: %s | Count: %d", anomaly.ip.c_str(), anomaly.packetCount);
    }
    
    refresh();
}