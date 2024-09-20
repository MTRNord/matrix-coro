#pragma once
#include <string>
#include <curl/curl.h>

inline std::string url_encode(const std::string &decoded) {
    const auto encoded_value = curl_easy_escape(nullptr, decoded.c_str(), static_cast<int>(decoded.length()));
    std::string result(encoded_value);
    curl_free(encoded_value);
    return result;
}
