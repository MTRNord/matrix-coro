#include "matrix_coro.hpp"
#include "spdlog/spdlog.h"

#include <iostream>
#include <json/json.h>

static size_t WriteCallback(void *contents, const size_t size, const size_t nmemb, void *userp) {
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

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to find well_known: " + std::string(curl_easy_strerror(res)));
    }

    Json::Value root;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, root); !parse_status) {
        throw std::runtime_error("failed to parse well_known");
    }
    WellKnownResponse response;
    response.homeserver = root["m.homeserver"]["base_url"].asString();
    response.identity_server = root["m.identity_server"]["base_url"].asString();
    co_return response;
}

cppcoro::task<AuthIssuerResponse> Client::fetch_auth_issuer(const std::string &cs_endpoint) const {
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    // Throw if the cs_endpoint doesnt start with https:// or if it contains a trailing slash or if it is empty or it contains _matrix/client
    if (cs_endpoint.find("https://") == std::string::npos || cs_endpoint.find("_matrix/client") != std::string::npos ||
        cs_endpoint.back() == '/') {
        throw std::runtime_error("invalid cs_endpoint");
    }

    const auto endpoint = cs_endpoint + "/_matrix/client/unstable/org.matrix.msc2965/auth_issuer";

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to find auth_issuer information: " + std::string(curl_easy_strerror(res)));
    }

    Json::Value root;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, root); !parse_status) {
        throw std::runtime_error("failed to parse auth_issuer information");
    }
    AuthIssuerResponse response;
    response.issuer = root["issuer"].asString();
    co_return response;
}

cppcoro::task<ClientRegistrationResponse> Client::register_client(const std::string &auth_endpoint,
                                                                  const ClientRegistrationData &registration_data)
const {
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    if (auth_endpoint.find("https://") == std::string::npos || auth_endpoint.find("_matrix/client") != std::string::npos
        ||
        auth_endpoint.back() == '/') {
        throw std::runtime_error("invalid auth_endpoint");
    }

    const auto endpoint = auth_endpoint + "/oauth2/registration";

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    // Make it a POST request
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Convert the registration data to a JSON string
    Json::Value root;
    root["application_type"] = registration_data.application_type;
    root["client_name"] = registration_data.client_name;
    root["redirect_uris"] = Json::arrayValue;
    for (const auto &uri: registration_data.redirect_uris) {
        root["redirect_uris"].append(uri);
    }
    root["response_types"] = Json::arrayValue;
    for (const auto &response_type: registration_data.response_types) {
        root["response_types"].append(response_type);
    }
    root["token_endpoint_auth_method"] = registration_data.token_endpoint_auth_method;
    root["client_uri"] = registration_data.client_uri;

    // Convert the JSON to a string
    Json::StreamWriterBuilder writer;
    const std::string json_str = Json::writeString(writer, root);

    // Set the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());

    // Set the Content-Type header
    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to find auth_issuer information: " + std::string(curl_easy_strerror(res)));
    }

    Json::Value resp_root;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, resp_root); !parse_status) {
        throw std::runtime_error("failed to parse auth_issuer information");
    }
    ClientRegistrationResponse response;
    response.client_id = resp_root["client_id"].asString();
    response.client_id_issued_at = resp_root["client_id_issued_at"].asInt();
    co_return response;
}
