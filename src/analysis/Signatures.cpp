#include "analysis/Signatures.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>

namespace pm {

const char* severityName(Severity s) {
    switch (s) {
    case Severity::Low: return "low";
    case Severity::Medium: return "medium";
    case Severity::High: return "high";
    }
    return "?";
}

namespace {

int hexValue(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) a++;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) b--;
    return s.substr(a, b - a);
}

}  // namespace

bool parseContent(const std::string& text, std::string& bytes, std::string& error) {
    bytes.clear();
    for (size_t i = 0; i < text.size(); i++) {
        char c = text[i];
        if (c == '\\') {
            if (i + 1 >= text.size()) {
                error = "a backslash at the end of the content";
                return false;
            }
            char e = text[++i];
            if (e != '\\' && e != '"' && e != '|') {
                error = std::string("unknown escape \\") + e + " (use |xx| for bytes)";
                return false;
            }
            bytes += e;
        } else if (c == '|') {
            size_t close = text.find('|', i + 1);
            if (close == std::string::npos) {
                error = "a | without its closing |";
                return false;
            }
            int nibbles = 0, value = 0;
            for (size_t j = i + 1; j < close; j++) {
                char h = text[j];
                if (h == ' ') continue;
                int v = hexValue(h);
                if (v < 0) {
                    error = std::string("'") + h + "' is not a hex digit";
                    return false;
                }
                value = value * 16 + v;
                if (++nibbles == 2) {
                    bytes += char(value);
                    nibbles = value = 0;
                }
            }
            if (nibbles != 0) {
                error = "an odd number of hex digits";
                return false;
            }
            i = close;
        } else {
            bytes += c;
        }
    }
    if (bytes.empty()) {
        error = "empty content";
        return false;
    }
    return true;
}

bool SignatureSet::parse(const std::string& text, std::string& error) {
    sigs_.clear();
    std::istringstream in(text);
    std::string raw;
    int lineNo = 0;
    while (std::getline(in, raw)) {
        lineNo++;
        std::string line = trim(raw);
        if (line.empty() || line[0] == '#') continue;
        auto fail = [&](const std::string& why) {
            error = "line " + std::to_string(lineNo) + ": " + why;
            return false;
        };

        size_t quote = line.find('"');
        if (quote == std::string::npos) {
            // The original format: the whole line is the pattern.
            if (line.size() > kMaxExactContent) return fail("pattern longer than " + std::to_string(kMaxExactContent) + " bytes");
            Signature s;
            s.name = line;
            s.content = line;
            s.message = "Payload contains \"" + line + "\"";
            sigs_.push_back(std::move(s));
            continue;
        }

        Signature s;
        std::istringstream head(line.substr(0, quote));
        std::string severity;
        head >> severity >> s.name;
        std::string extra;
        if (severity.empty() || s.name.empty() || (head >> extra)) {
            return fail("expected <severity> <name> \"<content>\"");
        }
        if (severity == "low") s.severity = Severity::Low;
        else if (severity == "medium") s.severity = Severity::Medium;
        else if (severity == "high") s.severity = Severity::High;
        else return fail("severity must be low, medium or high, not '" + severity + "'");

        // The content runs to the next quote that isn't escaped.
        size_t end = quote + 1;
        while (end < line.size() && line[end] != '"') end += line[end] == '\\' ? 2 : 1;
        if (end >= line.size()) return fail("the content has no closing quote");
        std::string why;
        if (!parseContent(line.substr(quote + 1, end - quote - 1), s.content, why)) return fail(why);

        std::string rest = line.substr(end + 1);
        size_t colon = rest.find(':');
        std::istringstream opts(rest.substr(0, colon));
        std::string opt;
        while (opts >> opt) {
            if (opt == "nocase") s.nocase = true;
            else return fail("unknown option '" + opt + "'");
        }
        if (!s.nocase && s.content.size() > kMaxExactContent) {
            return fail("content longer than " + std::to_string(kMaxExactContent) + " bytes must be nocase");
        }
        s.message = colon == std::string::npos ? "Matched " + s.name : trim(rest.substr(colon + 1));
        sigs_.push_back(std::move(s));
    }
    compile();
    return true;
}

bool SignatureSet::loadFile(const std::string& path, std::string& error) {
    std::ifstream f(path);
    if (!f) {
        error = "can't open " + path;
        return false;
    }
    std::stringstream ss;
    ss << f.rdbuf();
    std::string why;
    if (!parse(ss.str(), why)) {
        error = path + ", " + why;
        return false;
    }
    return true;
}

void SignatureSet::compile() {
    std::vector<std::string> contents;
    anyExact_ = false;
    longest_ = 0;
    for (const Signature& sig : sigs_) {
        contents.push_back(sig.content);
        longest_ = std::max(longest_, sig.content.size());
        anyExact_ |= !sig.nocase;
    }
    matcher_.build(contents, true);
}

bool SignatureSet::exactAt(const Stream& st, const uint8_t* data, size_t end, const std::string& content) {
    // The match is the content.size() bytes ending at data[end]; the start
    // may lie in the tail kept from earlier packets.
    const long start = long(end) + 1 - long(content.size());
    for (size_t j = 0; j < content.size(); j++) {
        const long at = start + long(j);
        uint8_t b;
        if (at >= 0) {
            b = data[at];
        } else {
            const long t = long(st.tailLen) + at;
            if (t < 0) return false;
            b = st.tail[t];
        }
        if (b != static_cast<uint8_t>(content[j])) return false;
    }
    return true;
}

void SignatureSet::keepTail(Stream& st, const uint8_t* data, size_t len) {
    constexpr size_t cap = Stream::kTail;
    if (len >= cap) {
        std::memcpy(st.tail, data + len - cap, cap);
        st.tailLen = uint8_t(cap);
        return;
    }
    const size_t keepOld = std::min<size_t>(st.tailLen, cap - len);
    std::memmove(st.tail, st.tail + st.tailLen - keepOld, keepOld);
    if (len) std::memcpy(st.tail + keepOld, data, len);
    st.tailLen = uint8_t(keepOld + len);
}

}  // namespace pm
