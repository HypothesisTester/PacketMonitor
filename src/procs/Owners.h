// Which app owns a connection. The operating system's socket table maps each
// local address and port to a process: /proc on Linux, libproc on macOS.
// Recorded captures can carry the answers alongside, in a ".apps" file.
#pragma once

#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "core/Packet.h"

namespace pm {

struct Owner {
    int pid = 0;
    std::string app;
};

class OwnerLookup {
public:
    virtual ~OwnerLookup() = default;
    /** Looks up the process behind the local end of a connection. */
    virtual bool find(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp,
                      uint16_t remotePort, Owner& out) = 0;
    /** Asks for fresh data soon, e.g. after a lookup for a new connection failed. */
    virtual void requestRefresh() {}
};

/** One socket from the system's table. */
struct SocketEntry {
    uint8_t proto = 0;
    IpAddr local, remote;  // zero address means "any"
    uint16_t localPort = 0, remotePort = 0;
    int pid = 0;
    uint32_t app = 0;  // index into SocketTable::apps
};

/** A point-in-time copy of the socket table, indexed for lookups. */
class SocketTable {
public:
    void add(SocketEntry e) { entries_.push_back(e); }
    uint32_t internApp(const std::string& name);
    void index();
    bool find(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp, uint16_t remotePort,
              Owner& out) const;
    size_t size() const { return entries_.size(); }
    std::vector<SocketEntry>& entries() { return entries_; }

private:
    std::vector<SocketEntry> entries_;
    std::vector<std::string> apps_;
    std::unordered_map<std::string, uint32_t> appIds_;
    std::unordered_multimap<uint32_t, uint32_t> byPort_;  // proto << 16 | port -> entry
};

/** Reads the live socket table; false with a reason where that isn't possible. */
bool readSystemSockets(SocketTable& table, std::string& error);

/** Keeps a socket table fresh on a background thread. */
class SystemOwners : public OwnerLookup {
public:
    SystemOwners();
    ~SystemOwners() override;
    bool find(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp, uint16_t remotePort,
              Owner& out) override;
    void requestRefresh() override;
    /** Why lookups don't work, or empty if they do. */
    std::string problem() const;

private:
    void run();

    mutable std::mutex mu_;
    std::condition_variable cv_;
    std::shared_ptr<const SocketTable> table_;
    std::string problem_;
    bool wanted_ = false;
    bool stop_ = false;
    std::thread thread_;
};

/** Answers from a ".apps" file written while recording a capture. */
class RecordedOwners : public OwnerLookup {
public:
    bool load(const std::string& path, std::string& error);
    bool find(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp, uint16_t remotePort,
              Owner& out) override;
    size_t size() const { return map_.size(); }
    /** The recording machine's addresses: from "# local" lines and each connection's local end. */
    const std::vector<IpAddr>& localAddresses() const { return local_; }

    /** One line of the file format. */
    static std::string line(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp,
                            uint16_t remotePort, const std::string& app);

private:
    static std::string key(uint8_t proto, const IpAddr& localIp, uint16_t localPort, const IpAddr& remoteIp,
                           uint16_t remotePort);
    std::unordered_map<std::string, std::string> map_;
    std::vector<IpAddr> local_;
};

/**
 * The app a macOS executable belongs to: the outermost ".app" bundle in its
 * path, so "Google Chrome Helper" inside Google Chrome.app is "Google Chrome".
 * Falls back to the file name.
 */
std::string appNameFromPath(const std::string& path);

/** Parses one line of /proc/net/tcp, tcp6, udp or udp6. */
bool parseProcNetLine(const std::string& line, uint8_t proto, bool v6, SocketEntry& out, unsigned long& inode);

}  // namespace pm
