#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>

namespace fs = std::filesystem;

void replaceAll(std::string& str, const std::string& from, const std::string& to) {
    if (from.empty()) return;  // 空文字列を置換対象にすると無限ループになるので防ぐ

    size_t pos = 0;
    while ((pos = str.find(from, pos)) != std::string::npos) {
        str.replace(pos, from.length(), to);
        pos += to.length();  // 置換した分だけ進める
    }
}

bool starts_with(const std::string& line, const std::string& prefix) {
    return line.find(prefix) == 0;
}

bool is_blank_or_indent(const std::string& line) {
    return line.empty() || std::isspace(line[0]);
}

bool contains_paren_or_eq(const std::string& line) {
    bool a=line.find('(') != std::string::npos || line.find('=') != std::string::npos || line.find(';') != std::string::npos;
    return a && line.find(' ') != std::string::npos;
}

std::string remove_keywords(const std::string& line) {
    std::string result = std::regex_replace(line, std::regex("\\b(static|inline|extern)\\b"), "");
    return std::regex_replace(result, std::regex(" +"), " "); // 余分なスペース除去
}

void process_file(const fs::path& input_path, const fs::path& output_path) {
    std::ifstream in(input_path);
    std::ofstream out(output_path);

    if (!in || !out) {
        std::cerr << "Failed to open " << input_path << " or " << output_path << '\n';
        return;
    }

    std::string line;
    bool in_multiline_comment = false;
    bool in_backslash_continued_directive = false;
    bool in_plusplus = false;

    while (std::getline(in, line)) {
        std::string trimmed = std::regex_replace(line, std::regex("^\\s+"), "");

        if (in_plusplus && starts_with(trimmed, "#")==false) {
            out << "// "<<line << '\n';
        }
        else if (in_plusplus && starts_with(trimmed, "#")) {
            out << "// " << line << '\n';
            in_plusplus = false;
        }
        else if (in_multiline_comment) {
            out << line << '\n';
            if (line.find("*/") != std::string::npos) {
                in_multiline_comment = false;
            }
        }
        else if (starts_with(trimmed, "/*")) {
            out << line << '\n';
            if (line.find("*/") == std::string::npos) {
                in_multiline_comment = true;
            }
        }
        else if (starts_with(trimmed, "#") && line.find("include")!= std::string::npos && (line.find("\"") != std::string::npos || line.find("psa") != std::string::npos || line.find("mbed") != std::string::npos)) {
            replaceAll(line, ".h", ".hpp");
            replaceAll(line, ".c", ".cpp");
            out << line << '\n';
        }
        else if (starts_with(trimmed, "#") && line.find("plusplus") != std::string::npos) {
            out << "// "<<line << '\n';
            in_plusplus = true;
        }
        else if (starts_with(trimmed, "#")) {
            out << line << '\n';
            in_backslash_continued_directive = line.back() == '\\';
            in_plusplus = false;
        }
        else if (starts_with(trimmed, "//")) {
            out << line << '\n';
            in_backslash_continued_directive = false;
        }
        else if (line=="") {
            in_backslash_continued_directive = false;
            out <<  '\n';
        }
        else if (in_backslash_continued_directive) {
            out << line << '\n';
            in_backslash_continued_directive = line.back() == '\\';
        }
        else if (is_blank_or_indent(line)) {
            out << line << '\n';
        }
        else if (!contains_paren_or_eq(line)) {
            out << line << '\n';
        }
        else if(line.find("typedef")== std::string::npos && line.find("}") == std::string::npos) {
            std::string cleaned = remove_keywords(line);
            out << "static inline " << cleaned << '\n';
        }
        else {
            out << line << '\n';
        }
    }
}

bool ends_with(const std::string& str, const std::string& suffix) {
    if (suffix.size() > str.size()) return false;
    return str.compare(str.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string changeExtension(const std::string& filename, const std::string& newExt) {
    size_t pos = filename.rfind('.');
    if (pos == std::string::npos) {
        return filename;
    }
    return filename.substr(0, pos + 1) + newExt;
}

bool isDirectory(const std::string& path) {
    namespace fs = std::filesystem;
    return fs::exists(path) && fs::is_directory(path);
}


int main() {
    std::vector<std::string> paths;
    std::string out = "out";

    fs::create_directory(out);

    paths.push_back(".");
    paths.push_back("in");
    for (auto path : paths) {
        if (!isDirectory(path))continue;
        for (const auto& entry : fs::directory_iterator(path)) {
            if (entry.is_regular_file()) {
                std::string input = entry.path().string();
                std::string output = out + "/" + entry.path().filename().string();

                if (ends_with(input, ".c")) {
                    output = changeExtension(output, "cpp");
                }
                else if (ends_with(input, ".h")) {
                    output = changeExtension(output, "hpp");
                }
                else {
                    continue;
                }

                std::cout << "Processing: " << input << " -> " << output << '\n';
                process_file(input, output);
            }
        }
    }
    return 0;
}



