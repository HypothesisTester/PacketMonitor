// macOS: walks every process's file descriptors with libproc (as lsof does)
// and reads the addresses of its internet sockets.
#include <arpa/inet.h>
#include <libproc.h>
#include <sys/param.h>
#include <netinet/in.h>
#include <sys/proc_info.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <vector>

#include "procs/Owners.h"

namespace pm {
namespace {

IpAddr fromSockAddr(const in_sockinfo& ini, bool foreign) {
    IpAddr a;
    if (ini.insi_vflag & INI_IPV4) {
        const in_addr& v4 = foreign ? ini.insi_faddr.ina_46.i46a_addr4 : ini.insi_laddr.ina_46.i46a_addr4;
        a.family = 4;
        std::memcpy(a.bytes.data(), &v4, 4);
    } else {
        const in6_addr& v6 = foreign ? ini.insi_faddr.ina_6 : ini.insi_laddr.ina_6;
        a.family = 6;
        std::memcpy(a.bytes.data(), &v6, 16);
    }
    return a.withoutScope();
}

std::string appName(pid_t pid) {
    char path[PROC_PIDPATHINFO_MAXSIZE];
    if (proc_pidpath(pid, path, sizeof path) > 0) return appNameFromPath(path);
    char name[2 * MAXCOMLEN + 1] = {};
    if (proc_name(pid, name, sizeof name) > 0) return name;
    return "pid " + std::to_string(pid);
}

}  // namespace

bool readSystemSockets(SocketTable& table, std::string& error) {
    int count = proc_listallpids(nullptr, 0);
    if (count <= 0) {
        error = "can't list processes";
        return false;
    }
    std::vector<pid_t> pids(size_t(count) + 64);
    count = proc_listallpids(pids.data(), int(pids.size() * sizeof(pid_t)));
    if (count <= 0) {
        error = "can't list processes";
        return false;
    }
    pids.resize(size_t(count));

    std::vector<proc_fdinfo> fds;
    for (pid_t pid : pids) {
        if (pid <= 0) continue;
        int bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nullptr, 0);
        if (bytes <= 0) continue;  // gone, or not ours to inspect without root
        fds.resize(size_t(bytes) / sizeof(proc_fdinfo) + 16);
        bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fds.data(), int(fds.size() * sizeof(proc_fdinfo)));
        if (bytes <= 0) continue;
        size_t n = size_t(bytes) / sizeof(proc_fdinfo);

        bool named = false;
        uint32_t app = 0;
        for (size_t i = 0; i < n; i++) {
            if (fds[i].proc_fdtype != PROX_FDTYPE_SOCKET) continue;
            socket_fdinfo si;
            int got = proc_pidfdinfo(pid, fds[i].proc_fd, PROC_PIDFDSOCKETINFO, &si, PROC_PIDFDSOCKETINFO_SIZE);
            if (got != PROC_PIDFDSOCKETINFO_SIZE) continue;
            const socket_info& s = si.psi;
            if (s.soi_family != AF_INET && s.soi_family != AF_INET6) continue;

            const in_sockinfo* ini = nullptr;
            uint8_t proto = 0;
            if (s.soi_kind == SOCKINFO_TCP) {
                ini = &s.soi_proto.pri_tcp.tcpsi_ini;
                proto = kProtoTcp;
            } else if (s.soi_kind == SOCKINFO_IN && s.soi_protocol == IPPROTO_UDP) {
                ini = &s.soi_proto.pri_in;
                proto = kProtoUdp;
            } else {
                continue;
            }

            if (!named) {
                app = table.internApp(appName(pid));
                named = true;
            }
            SocketEntry e;
            e.proto = proto;
            e.local = fromSockAddr(*ini, false);
            e.remote = fromSockAddr(*ini, true);
            // Ports are stored in network byte order in an int.
            e.localPort = ntohs(uint16_t(ini->insi_lport));
            e.remotePort = ntohs(uint16_t(ini->insi_fport));
            e.pid = pid;
            e.app = app;
            table.add(e);
        }
    }
    if (geteuid() != 0 && table.size() == 0) {
        error = "run with sudo to see which app owns each connection";
        return false;
    }
    return true;
}

}  // namespace pm
