// Linux: sockets from /proc/net/*, owners by matching socket inodes against
// the file descriptors in /proc/<pid>/fd.
#include <dirent.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <fstream>
#include <unordered_map>

#include "procs/Owners.h"

namespace pm {
namespace {

bool isNumber(const char* s) {
    if (!*s) return false;
    for (; *s; s++) {
        if (!std::isdigit(static_cast<unsigned char>(*s))) return false;
    }
    return true;
}

std::string processName(int pid) {
    std::ifstream f("/proc/" + std::to_string(pid) + "/comm");
    std::string name;
    std::getline(f, name);
    return name.empty() ? "pid " + std::to_string(pid) : name;
}

}  // namespace

bool readSystemSockets(SocketTable& table, std::string& error) {
    struct Source {
        const char* path;
        uint8_t proto;
        bool v6;
    };
    static const Source sources[] = {
        {"/proc/net/tcp", kProtoTcp, false},
        {"/proc/net/tcp6", kProtoTcp, true},
        {"/proc/net/udp", kProtoUdp, false},
        {"/proc/net/udp6", kProtoUdp, true},
    };

    std::unordered_map<unsigned long, std::vector<SocketEntry>> byInode;
    bool any = false;
    for (const auto& src : sources) {
        std::ifstream f(src.path);
        if (!f) continue;
        any = true;
        std::string line;
        std::getline(f, line);  // column titles
        while (std::getline(f, line)) {
            SocketEntry e;
            unsigned long inode = 0;
            if (parseProcNetLine(line, src.proto, src.v6, e, inode) && inode != 0) byInode[inode].push_back(e);
        }
    }
    if (!any) {
        error = "can't read /proc/net";
        return false;
    }

    DIR* proc = opendir("/proc");
    if (!proc) {
        error = "can't read /proc";
        return false;
    }
    size_t owned = 0;
    std::unordered_map<int, uint32_t> appOf;
    while (dirent* d = readdir(proc)) {
        if (!isNumber(d->d_name)) continue;
        int pid = std::atoi(d->d_name);
        std::string fdDir = std::string("/proc/") + d->d_name + "/fd";
        DIR* fds = opendir(fdDir.c_str());
        if (!fds) continue;  // not ours to read without root
        while (dirent* fd = readdir(fds)) {
            if (fd->d_name[0] == '.') continue;
            char target[64];
            std::string link = fdDir + "/" + fd->d_name;
            ssize_t n = readlink(link.c_str(), target, sizeof target - 1);
            if (n <= 8) continue;
            target[n] = 0;
            if (std::strncmp(target, "socket:[", 8) != 0) continue;
            unsigned long inode = std::strtoul(target + 8, nullptr, 10);
            auto it = byInode.find(inode);
            if (it == byInode.end()) continue;
            auto app = appOf.find(pid);
            if (app == appOf.end()) app = appOf.emplace(pid, table.internApp(processName(pid))).first;
            for (SocketEntry e : it->second) {
                e.pid = pid;
                e.app = app->second;
                table.add(e);
            }
            byInode.erase(it);  // the first process wins for shared sockets
            owned++;
        }
        closedir(fds);
    }
    closedir(proc);
    if (owned == 0 && geteuid() != 0) {
        error = "run as root to see which app owns each connection";
        return false;
    }
    return true;
}

}  // namespace pm
