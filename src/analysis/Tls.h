// Reads the server name (SNI) from the start of a TLS connection. The client
// sends it in clear text in its first message, so encrypted connections still
// say which site they are for.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace pm {

enum class SniResult {
    Found,     // host is set
    NeedMore,  // looks like a ClientHello, but the name isn't in the bytes so far
    NoSni,     // a complete ClientHello without a server name
    NotTls,    // not the start of a TLS handshake
};

/** data is the first bytes the client sent on the connection, in order. */
SniResult extractSni(const uint8_t* data, size_t len, std::string& host);

/** True if the bytes could be the start of a TLS handshake record. */
bool looksLikeTlsHandshake(const uint8_t* data, size_t len);

}  // namespace pm
