// Payload signatures: byte patterns that suggest an attack or a risky
// practice, loaded from a text file and matched with Aho–Corasick.
//
// File format, one signature per line:
//
//   <severity> <name> "<content>" [nocase] [: <message>]
//
// severity is low, medium or high. In content, |0d 0a| writes bytes in hex,
// and \" \\ \| stand for the characters themselves. nocase matches ASCII
// letters in any case. Blank lines and lines starting with # are ignored.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "analysis/AhoCorasick.h"

namespace pm {

enum class Severity : uint8_t { Low, Medium, High };
const char* severityName(Severity s);

struct Signature {
    std::string name;
    std::string content;  // raw bytes
    bool nocase = false;
    Severity severity = Severity::Medium;
    std::string message;
};

class SignatureSet {
public:
    /** Parses signature text; on failure, error names the line. */
    bool parse(const std::string& text, std::string& error);
    bool loadFile(const std::string& path, std::string& error);

    const std::vector<Signature>& signatures() const { return sigs_; }
    size_t size() const { return sigs_.size(); }
    size_t longestContent() const { return longest_; }

    /**
     * Scan state for one direction of one stream: the automaton's state and
     * the last bytes seen, for checking exact-case matches that began in an
     * earlier packet.
     */
    struct Stream {
        static constexpr size_t kTail = 127;
        uint32_t state = AhoCorasick::kStart;
        uint8_t tailLen = 0;
        uint8_t tail[kTail];
    };
    /** The longest exact-case content a signature may have. */
    static constexpr size_t kMaxExactContent = Stream::kTail + 1;

    /** Scans data, continuing from stream, calling onMatch(signatureIndex) for each match. */
    template <class OnMatch>
    void scan(Stream& stream, const uint8_t* data, size_t len, OnMatch&& onMatch) const {
        // One case-folded pass finds every candidate; exact-case signatures
        // are then confirmed against the original bytes.
        stream.state = matcher_.scan(stream.state, data, len, [&](uint32_t id, size_t end) {
            const Signature& sig = sigs_[id];
            if (sig.nocase || exactAt(stream, data, end, sig.content)) onMatch(id);
        });
        if (anyExact_) keepTail(stream, data, len);
    }

private:
    void compile();
    static bool exactAt(const Stream& st, const uint8_t* data, size_t end, const std::string& content);
    static void keepTail(Stream& st, const uint8_t* data, size_t len);

    std::vector<Signature> sigs_;
    AhoCorasick matcher_;
    bool anyExact_ = false;
    size_t longest_ = 0;
};

/** Parses the quoted content syntax (without the quotes). */
bool parseContent(const std::string& text, std::string& bytes, std::string& error);

}  // namespace pm
