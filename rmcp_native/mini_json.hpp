// ============================================================================
//  mini_json — a tiny, dependency-free JSON helper for the RMCP C ABI.
//  Handles exactly what the binding needs: parsing flat JSON objects (string and
//  int values, plus a one-level "attrs" string map), parsing string arrays, and
//  writing small result objects. NOT a general JSON library — scoped on purpose.
//  Built on the RMCP engine by BLCKBX.
// ============================================================================
#ifndef RMCP_MINI_JSON_HPP
#define RMCP_MINI_JSON_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <cctype>
#include <cstdlib>

namespace minijson {

// ── tiny parser ──

inline void skip_ws(const std::string& s, size_t& i) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
}

// Parse a JSON string token starting at s[i] == '"'. Handles basic escapes.
inline std::string parse_string(const std::string& s, size_t& i) {
    std::string out;
    if (i >= s.size() || s[i] != '"') return out;
    ++i;  // opening quote
    while (i < s.size() && s[i] != '"') {
        char ch = s[i];
        if (ch == '\\' && i + 1 < s.size()) {
            char esc = s[i + 1];
            switch (esc) {
                case 'n': out.push_back('\n'); break;
                case 't': out.push_back('\t'); break;
                case 'r': out.push_back('\r'); break;
                case '"': out.push_back('"'); break;
                case '\\': out.push_back('\\'); break;
                case '/': out.push_back('/'); break;
                default: out.push_back(esc); break;
            }
            i += 2;
        } else {
            out.push_back(ch);
            ++i;
        }
    }
    if (i < s.size()) ++i;  // closing quote
    return out;
}

// Skip a JSON value we don't care about (object, array, string, number, literal).
inline void skip_value(const std::string& s, size_t& i);

inline void skip_container(const std::string& s, size_t& i, char open, char close) {
    int depth = 0;
    while (i < s.size()) {
        char ch = s[i];
        if (ch == '"') { parse_string(s, i); continue; }
        if (ch == open) ++depth;
        else if (ch == close) { --depth; ++i; if (depth == 0) return; continue; }
        ++i;
    }
}

inline void skip_value(const std::string& s, size_t& i) {
    skip_ws(s, i);
    if (i >= s.size()) return;
    char ch = s[i];
    if (ch == '"') { parse_string(s, i); }
    else if (ch == '{') { skip_container(s, i, '{', '}'); }
    else if (ch == '[') { skip_container(s, i, '[', ']'); }
    else {
        while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ']') ++i;
    }
}

// A parsed flat object: top-level string values, plus an optional nested string map.
struct Object {
    std::unordered_map<std::string, std::string> str_values;
    std::unordered_map<std::string, long> int_values;
    std::unordered_map<std::string, std::unordered_map<std::string, std::string>> maps;

    std::string get(const std::string& key, const std::string& dflt) const {
        auto it = str_values.find(key);
        return it == str_values.end() ? dflt : it->second;
    }
    long get_int(const std::string& key, long dflt) const {
        auto it = int_values.find(key);
        if (it != int_values.end()) return it->second;
        auto s = str_values.find(key);
        if (s != str_values.end()) { try { return std::stol(s->second); } catch (...) {} }
        return dflt;
    }
    std::unordered_map<std::string, std::string> get_string_map(const std::string& key) const {
        auto it = maps.find(key);
        return it == maps.end() ? std::unordered_map<std::string, std::string>{} : it->second;
    }
};

// Parse a nested one-level string map: { "k": "v", "k2": "v2" } (values coerced to string).
inline std::unordered_map<std::string, std::string> parse_flat_map(const std::string& s, size_t& i) {
    std::unordered_map<std::string, std::string> m;
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '{') return m;
    ++i;
    while (i < s.size()) {
        skip_ws(s, i);
        if (i < s.size() && s[i] == '}') { ++i; break; }
        if (s[i] != '"') { skip_value(s, i); }
        std::string key = parse_string(s, i);
        skip_ws(s, i);
        if (i < s.size() && s[i] == ':') ++i;
        skip_ws(s, i);
        // value: string, number, or literal -> coerce to string
        std::string val;
        if (i < s.size() && s[i] == '"') {
            val = parse_string(s, i);
        } else {
            size_t start = i;
            while (i < s.size() && s[i] != ',' && s[i] != '}') ++i;
            val = s.substr(start, i - start);
            // trim
            while (!val.empty() && std::isspace(static_cast<unsigned char>(val.back()))) val.pop_back();
        }
        m[key] = val;
        skip_ws(s, i);
        if (i < s.size() && s[i] == ',') ++i;
    }
    return m;
}

inline Object parse_object(const std::string& s) {
    Object obj;
    size_t i = 0;
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '{') return obj;
    ++i;
    while (i < s.size()) {
        skip_ws(s, i);
        if (i < s.size() && s[i] == '}') { ++i; break; }
        if (s[i] != '"') { skip_value(s, i); skip_ws(s, i); if (i<s.size() && s[i]==',') {++i; continue;} else break; }
        std::string key = parse_string(s, i);
        skip_ws(s, i);
        if (i < s.size() && s[i] == ':') ++i;
        skip_ws(s, i);
        if (i >= s.size()) break;
        char ch = s[i];
        if (ch == '"') {
            obj.str_values[key] = parse_string(s, i);
        } else if (ch == '{') {
            obj.maps[key] = parse_flat_map(s, i);
        } else if (ch == '[') {
            skip_value(s, i);  // arrays at top level not needed here
        } else {
            size_t start = i;
            while (i < s.size() && s[i] != ',' && s[i] != '}') ++i;
            std::string num = s.substr(start, i - start);
            while (!num.empty() && std::isspace(static_cast<unsigned char>(num.back()))) num.pop_back();
            obj.str_values[key] = num;
            try { obj.int_values[key] = std::stol(num); } catch (...) {}
        }
        skip_ws(s, i);
        if (i < s.size() && s[i] == ',') ++i;
    }
    return obj;
}

// Parse a top-level JSON array of strings: ["a","b"].
inline std::vector<std::string> parse_string_array(const std::string& s) {
    std::vector<std::string> out;
    size_t i = 0;
    skip_ws(s, i);
    if (i >= s.size() || s[i] != '[') return out;
    ++i;
    while (i < s.size()) {
        skip_ws(s, i);
        if (i < s.size() && s[i] == ']') { ++i; break; }
        if (s[i] == '"') out.push_back(parse_string(s, i));
        else skip_value(s, i);
        skip_ws(s, i);
        if (i < s.size() && s[i] == ',') ++i;
    }
    return out;
}

// ── tiny writer ──

class Writer {
public:
    void begin() { os_ << '{'; first_ = true; }
    void end() { os_ << '}'; }

    void kv_str(const std::string& k, const std::string& v) {
        comma(); os_ << '"' << k << "\":\"" << escape(v) << '"';
    }
    void kv_int(const std::string& k, long v) {
        comma(); os_ << '"' << k << "\":" << v;
    }
    void kv_array_str(const std::string& k, const std::vector<std::string>& vals) {
        comma(); os_ << '"' << k << "\":[";
        for (size_t n = 0; n < vals.size(); ++n) {
            if (n) os_ << ',';
            os_ << '"' << escape(vals[n]) << '"';
        }
        os_ << ']';
    }
    void begin_array(const std::string& k) { comma(); os_ << '"' << k << "\":["; arr_first_ = true; }
    void end_array() { os_ << ']'; }
    void begin_object_in_array() { if (!arr_first_) os_ << ','; arr_first_ = false; os_ << '{'; first_ = true; }
    void end_object_in_array() { os_ << '}'; }

    std::string str() const { return os_.str(); }

private:
    std::ostringstream os_;
    bool first_ = true;
    bool arr_first_ = true;
    void comma() { if (!first_) os_ << ','; first_ = false; }
    static std::string escape(const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '"') o += "\\\"";
            else if (c == '\\') o += "\\\\";
            else if (c == '\n') o += "\\n";
            else o.push_back(c);
        }
        return o;
    }
};

}  // namespace minijson

#endif  // RMCP_MINI_JSON_HPP
