#include "analysis/Tls.h"

namespace pm {
namespace {

inline uint32_t be16(const uint8_t* p) { return uint32_t(p[0]) << 8 | p[1]; }
inline uint32_t be24(const uint8_t* p) { return uint32_t(p[0]) << 16 | uint32_t(p[1]) << 8 | p[2]; }

/** Reads fields of a buffer that may still be arriving. */
struct Reader {
    const uint8_t* d;
    size_t end;        // bytes we may read
    bool partial;      // true when end is where the data stops, not where the message stops
    size_t pos = 0;
    bool shortRead = false;

    bool need(size_t n) {
        if (pos + n <= end) return true;
        shortRead = true;
        return false;
    }
};

bool validHostChar(uint8_t c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '.' ||
           c == '_';
}

}  // namespace

bool looksLikeTlsHandshake(const uint8_t* d, size_t len) {
    return len >= 6 && d[0] == 0x16 && d[1] == 3 && d[2] <= 4 && d[5] == 1;
}

SniResult extractSni(const uint8_t* d, size_t len, std::string& host) {
    if (len < 6) return len == 0 || d[0] == 0x16 ? SniResult::NeedMore : SniResult::NotTls;
    if (!looksLikeTlsHandshake(d, len)) return SniResult::NotTls;

    size_t recLen = be16(d + 3);
    size_t recEnd = 5 + recLen;
    bool partial = len < recEnd;
    Reader r{d, partial ? len : recEnd, partial};
    auto more = [&] { return r.partial ? SniResult::NeedMore : SniResult::NoSni; };

    r.pos = 5;
    if (!r.need(4)) return more();
    size_t hsLen = be24(d + 6);
    r.pos = 9;
    if (hsLen < 38) return SniResult::NotTls;
    if (!r.need(2 + 32)) return more();  // client version and random
    r.pos += 34;

    if (!r.need(1)) return more();
    size_t sidLen = d[r.pos];
    r.pos += 1;
    if (sidLen > 32) return SniResult::NotTls;
    if (!r.need(sidLen)) return more();
    r.pos += sidLen;

    if (!r.need(2)) return more();
    size_t csLen = be16(d + r.pos);
    r.pos += 2;
    if (!r.need(csLen)) return more();
    r.pos += csLen;

    if (!r.need(1)) return more();
    size_t compLen = d[r.pos];
    r.pos += 1;
    if (!r.need(compLen)) return more();
    r.pos += compLen;

    if (!r.need(2)) return more();
    size_t extEnd = r.pos + 2 + be16(d + r.pos);
    r.pos += 2;
    if (!r.partial && extEnd > r.end) return SniResult::NotTls;

    while (r.pos < extEnd) {
        if (!r.need(4)) return more();
        uint32_t type = be16(d + r.pos);
        size_t extLen = be16(d + r.pos + 2);
        r.pos += 4;
        if (type != 0) {
            if (!r.need(extLen)) return more();
            r.pos += extLen;
            continue;
        }
        if (!r.need(extLen)) return more();
        size_t listEnd = r.pos + extLen;
        if (extLen < 2) return SniResult::NoSni;
        size_t p = r.pos + 2;
        while (p + 3 <= listEnd) {
            uint8_t nameType = d[p];
            size_t nameLen = be16(d + p + 1);
            p += 3;
            if (p + nameLen > listEnd) return SniResult::NoSni;
            if (nameType == 0 && nameLen > 0 && nameLen <= 253) {
                host.clear();
                for (size_t i = 0; i < nameLen; i++) {
                    uint8_t c = d[p + i];
                    if (!validHostChar(c)) return SniResult::NoSni;
                    host += char(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
                }
                return SniResult::Found;
            }
            p += nameLen;
        }
        return SniResult::NoSni;
    }
    return SniResult::NoSni;
}

}  // namespace pm
