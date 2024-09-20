#include "matrix_coro.hpp"
#include "spdlog/spdlog.h"

#include <iostream>

static size_t WriteCallback(void *contents, const size_t size, size_t nmemb, void *userp) {
    static_cast<std::string *>(userp)->append(static_cast<char *>(contents), size * nmemb);
    return size * nmemb;
}

cppcoro::task<WellKnownResponse> Client::fetch_wellknown(const std::string &homeserver) const {
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    // Add https as needed to the homeserver address
    std::string homeserver_https = homeserver;
    if (homeserver_https.find("https://") == std::string::npos) {
        homeserver_https = "https://" + homeserver_https;
    }
    auto well_known_url = homeserver_https + "/.well-known/matrix/client";

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, well_known_url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to find well_known: " + std::string(curl_easy_strerror(res)));
    }

    Json::Value root;
    Json::Reader reader;
    if (bool parse_status = reader.parse(str_buffer, root); !parse_status) {
        throw std::runtime_error("failed to parse well_known");
    }
    WellKnownResponse response;
    response.homeserver = root["m.homeserver"]["base_url"].asString();
    response.identity_server = root["m.identity_server"]["base_url"].asString();
    co_return response;
}
