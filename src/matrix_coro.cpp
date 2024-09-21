#include "matrix_coro.hpp"

#include <regex>

#include "spdlog/spdlog.h"
#include <json/json.h>

static size_t WriteCallback(void *contents, const size_t size, const size_t nmemb, void *userp) {
    static_cast<std::string *>(userp)->append(static_cast<char *>(contents), size * nmemb);
    return size * nmemb;
}

cppcoro::task<Json::Value> LoggedInClient::get(const std::string &url) const {
    const auto curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    if (token_data.access_token.empty()) {
        throw std::runtime_error("access token is empty");
    }

    spdlog::debug("Fetching url: {}", url);

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    // Set User-Agent
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    // Add Authorization header
    const auto access_token = token_data.access_token;
    curl_easy_setopt(curl, CURLOPT_XOAUTH2_BEARER, access_token.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BEARER);

    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to fetch \"" + url + "\": " + std::string(curl_easy_strerror(res)));
    }

    Json::Value root;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, root); !parse_status) {
        throw std::runtime_error("failed to parse json");
    }

    curl_easy_cleanup(curl);
    co_return root;
}

cppcoro::task<WhoamiResponse> LoggedInClient::whoami() const {
    auto homeserver = well_known.homeserver;

    // Add https as needed to the homeserver address
    std::string homeserver_https = homeserver;
    if (homeserver_https.find("https://") == std::string::npos) {
        homeserver_https = "https://" + homeserver_https;
    }
    spdlog::info("Fetching whoami from homeserver: {}", homeserver);
    auto endpoint = homeserver_https + "_matrix/client/v3/account/whoami";

    // Remove double slashes and make them single
    std::regex re("([^:])(//+)");
    endpoint = std::regex_replace(endpoint, re, "$1/");
    spdlog::debug("Whoami endpoint: {}", endpoint);

    const auto json = co_await get(endpoint);
    WhoamiResponse response;
    response.user_id = json["user_id"].asString();
    response.device_id = json["device_id"].asString();
    response.is_guest = json["is_guest"].asBool();

    co_return response;
}

cppcoro::task<std::string> Client::get_auth_url(std::string homeserver, std::string redirect_url,
                                                std::string state, std::string code_verifier,
                                                const ClientRegistrationData &registration_data) {
    // Get the well-known configuration
    const auto well_known = co_await fetch_wellknown(homeserver);
    spdlog::debug("Fetched well-known from homeserver: {}", well_known.homeserver);

    // Get the auth issuer information
    const auto [issuer] = co_await fetch_auth_issuer(well_known.homeserver);
    spdlog::debug("Fetched auth issuer from homeserver: {}", issuer);

    // Get the openid configuration
    const auto openid_configuration = co_await fetch_openid_configuration(issuer);

    // Register the client
    const auto client_registration = co_await register_client(openid_configuration.registration_endpoint,
                                                              registration_data);

    spdlog::info("Registered client with client_id: {}", client_registration.client_id);

    this->code_verifier = code_verifier;

    // Build the auth URL
    co_return this->generate_authorize_url(openid_configuration.authorization_endpoint, client_registration,
                                           redirect_url, state,
                                           code_verifier);
}

cppcoro::task<LoggedInClient> Client::exchange_token(const std::string &code, const std::string &redirect_url) const {
    const auto token_resp = co_await exchange_code_for_token(this->openid_configuration.token_endpoint, code,
                                                             this->code_verifier,
                                                             this->client_registration.client_id, redirect_url);

    if (token_resp.access_token.empty()) {
        throw std::runtime_error("access token is empty after exchange");
    }

    spdlog::info("Successfully exchanged code for token");

    const auto logged_in_client = LoggedInClient(token_resp, this->well_known);
    co_return logged_in_client;
}

cppcoro::task<Json::Value> Client::get(const std::string &url) const {
    const auto curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    spdlog::debug("Fetching url: {}", url);

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    // Set User-Agent
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to fetch \"" + url + "\": " + std::string(curl_easy_strerror(res)));
    }

    Json::Value json;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, json); !parse_status) {
        throw std::runtime_error("failed to parse json");
    }

    if (json.isMember("error")) {
        throw std::runtime_error("error: " + json["error"].asString() + ", error_description: " +
                                 json["error_description"].asString());
    }

    curl_easy_cleanup(curl);
    co_return json;
}

cppcoro::task<Json::Value> Client::post(const std::string &url, const std::string &data, const bool form_data) const {
    const auto curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    spdlog::debug("Fetching url: {}", url);

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    // Set User-Agent
    curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());

    // Add data to body and set to POST request type
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());

    // Set the Content-Type header
    curl_slist *headers = nullptr;
    if (form_data) {
        headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    } else {
        headers = curl_slist_append(headers, "Content-Type: application/json");
    }
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to fetch \"" + url + "\": " + std::string(curl_easy_strerror(res)));
    }

    Json::Value json;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, json); !parse_status) {
        throw std::runtime_error("failed to parse json");
    }

    if (json.isMember("error")) {
        throw std::runtime_error("error: " + json["error"].asString() + ", error_description: " +
                                 json["error_description"].asString());
    }

    curl_easy_cleanup(curl);
    co_return json;
}

cppcoro::task<WellKnownResponse> Client::fetch_wellknown(std::string homeserver) {
    spdlog::info("Fetching well-known from homeserver: {}", homeserver);

    // Add https as needed to the homeserver address
    std::string homeserver_https = homeserver;
    if (homeserver_https.find("https://") == std::string::npos) {
        homeserver_https = "https://" + homeserver_https;
    }
    auto endpoint = homeserver_https + "/.well-known/matrix/client";

    // Remove double slashes and make them single
    const std::regex re("([^:])(//+)");
    endpoint = std::regex_replace(endpoint, re, "$1/");

    const auto json = co_await get(endpoint);

    WellKnownResponse response;
    response.homeserver = json["m.homeserver"]["base_url"].asString();
    response.identity_server = json["m.identity_server"]["base_url"].asString();
    this->well_known = response;
    co_return response;
}

cppcoro::task<AuthIssuerResponse> Client::fetch_auth_issuer(std::string cs_endpoint) {
    if (cs_endpoint.find("https://") == std::string::npos || cs_endpoint.find("_matrix/client") != std::string::npos) {
        throw std::runtime_error("invalid cs_endpoint");
    }

    auto endpoint = cs_endpoint + "/_matrix/client/unstable/org.matrix.msc2965/auth_issuer";

    // Remove double slashes and make them single
    const std::regex re("([^:])(//+)");
    endpoint = std::regex_replace(endpoint, re, "$1/");

    const auto json = co_await get(endpoint);

    AuthIssuerResponse response;
    response.issuer = json["issuer"].asString();
    this->auth_issuer = response;
    co_return response;
}

cppcoro::task<ClientRegistrationResponse> Client::register_client(std::string registration_endpoint,
                                                                  const ClientRegistrationData &registration_data) {
    if (registration_endpoint.find("https://") == std::string::npos) {
        throw std::runtime_error("invalid registration endpoint");
    }

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
    root["contacts"] = Json::arrayValue;
    for (const auto &contact: registration_data.contacts) {
        root["contacts"].append(contact);
    }

    // Convert the JSON to a string
    Json::StreamWriterBuilder writer;
    const std::string json_str = Json::writeString(writer, root);

    const auto json = co_await post(registration_endpoint, json_str);
    ClientRegistrationResponse response;
    response.client_id = json["client_id"].asString();
    response.client_id_issued_at = json["client_id_issued_at"].asInt();
    this->client_registration = response;
    co_return response;
}

cppcoro::task<TokenResponse> Client::exchange_code_for_token(std::string token_endpoint,
                                                             const std::string &code,
                                                             const std::string &code_verifier,
                                                             const std::string &client_id,
                                                             const std::string &redirect_url) const {
    if (token_endpoint.find("https://") == std::string::npos) {
        throw std::runtime_error("invalid token_endpoint");
    }

    // Url encode the redirect URL
    const auto url_encoded_redirect_url = url_encode(redirect_url);

    // Build the request body
    const std::string post_fields = "grant_type=authorization_code&code=" + code + "&redirect_uri=" +
                                    url_encoded_redirect_url +
                                    "&client_id=" + client_id + "&code_verifier=" + code_verifier;

    const auto json = co_await post(token_endpoint, post_fields, true);

    if (json.isMember("error")) {
        throw std::runtime_error("error: " + json["error"].asString() + ", error_description: " +
                                 json["error_description"].asString());
    }

    TokenResponse response;
    response.access_token = json["access_token"].asString();
    response.expires_in = json["expires_in"].asInt();
    response.refresh_token = json["refresh_token"].asString();
    response.token_type = json["token_type"].asString();
    response.scope = json["scope"].asString();

    co_return response;
}

cppcoro::task<OpenIDConfiguration> Client::fetch_openid_configuration(std::string auth_endpoint) {
    spdlog::info("Fetching openid configuration from auth_endpoint: {}", auth_endpoint);

    if (auth_endpoint.find("https://") == std::string::npos || auth_endpoint.find("_matrix/client") !=
        std::string::npos) {
        throw std::runtime_error("invalid auth_endpoint");
    }

    auto endpoint = auth_endpoint + "/.well-known/openid-configuration";

    // Remove double slashes and make them single
    std::regex re("([^:])(//+)");
    endpoint = std::regex_replace(endpoint, re, "$1/");

    const auto json = co_await get(endpoint);

    OpenIDConfiguration response;
    response.issuer = json["issuer"].asString();
    response.authorization_endpoint = json["authorization_endpoint"].asString();
    response.token_endpoint = json["token_endpoint"].asString();
    response.jwks_uri = json["jwks_uri"].asString();
    response.registration_endpoint = json["registration_endpoint"].asString();

    for (const auto &scope: json["scopes_supported"]) {
        response.scopes_supported.push_back(scope.asString());
    }
    for (const auto &response_type: json["response_types_supported"]) {
        response.response_types_supported.push_back(response_type.asString());
    }
    for (const auto &response_mode: json["response_modes_supported"]) {
        response.response_modes_supported.push_back(response_mode.asString());
    }
    for (const auto &grant_type: json["grant_types_supported"]) {
        response.grant_types_supported.push_back(grant_type.asString());
    }
    for (const auto &token_endpoint_auth_method: json["token_endpoint_auth_methods_supported"]) {
        response.token_endpoint_auth_methods_supported.push_back(token_endpoint_auth_method.asString());
    }
    for (const auto &token_endpoint_auth_signing_alg: json["token_endpoint_auth_signing_alg_values_supported"]) {
        response.token_endpoint_auth_signing_alg_values_supported.push_back(
            token_endpoint_auth_signing_alg.asString());
    }
    response.revocation_endpoint = json["revocation_endpoint"].asString();
    for (const auto &revocation_endpoint_auth_method: json["revocation_endpoint_auth_methods_supported"]) {
        response.revocation_endpoint_auth_methods_supported.push_back(revocation_endpoint_auth_method.asString());
    }
    for (const auto &revocation_endpoint_auth_signing_alg: json[
             "revocation_endpoint_auth_signing_alg_values_supported"]) {
        response.revocation_endpoint_auth_signing_alg_values_supported.push_back(
            revocation_endpoint_auth_signing_alg.asString());
    }
    response.introspection_endpoint = json["introspection_endpoint"].asString();
    for (const auto &introspection_endpoint_auth_method: json["introspection_endpoint_auth_methods_supported"]) {
        response.introspection_endpoint_auth_methods_supported.push_back(
            introspection_endpoint_auth_method.asString());
    }
    for (const auto &introspection_endpoint_auth_signing_alg: json[
             "introspection_endpoint_auth_signing_alg_values_supported"]) {
        response.introspection_endpoint_auth_signing_alg_values_supported.push_back(
            introspection_endpoint_auth_signing_alg.asString());
    }
    for (const auto &code_challenge_method: json["code_challenge_methods_supported"]) {
        response.code_challenge_methods_supported.push_back(code_challenge_method.asString());
    }
    response.userinfo_endpoint = json["userinfo_endpoint"].asString();
    for (const auto &subject_type: json["subject_types_supported"]) {
        response.subject_types_supported.push_back(subject_type.asString());
    }
    for (const auto &id_token_signing_alg: json["id_token_signing_alg_values_supported"]) {
        response.id_token_signing_alg_values_supported.push_back(id_token_signing_alg.asString());
    }
    for (const auto &userinfo_signing_alg: json["userinfo_signing_alg_values_supported"]) {
        response.userinfo_signing_alg_values_supported.push_back(userinfo_signing_alg.asString());
    }
    for (const auto &display_value: json["display_values_supported"]) {
        response.display_values_supported.push_back(display_value.asString());
    }
    for (const auto &claim_type: json["claim_types_supported"]) {
        response.claim_types_supported.push_back(claim_type.asString());
    }
    for (const auto &claim: json["claims_supported"]) {
        response.claims_supported.push_back(claim.asString());
    }
    response.claims_parameter_supported = json["claims_parameter_supported"].asBool();
    response.request_parameter_supported = json["request_parameter_supported"].asBool();
    response.request_uri_parameter_supported = json["request_uri_parameter_supported"].asBool();
    for (const auto &prompt_value: json["prompt_values_supported"]) {
        response.prompt_values_supported.push_back(prompt_value.asString());
    }
    response.device_authorization_endpoint = json["device_authorization_endpoint"].asString();
    response.org_matrix_matrix_authentication_service_graphql_endpoint = json[
        "org.matrix.matrix_authentication_service_graphql_endpoint"].asString();
    response.account_management_uri = json["account_management_uri"].asString();
    for (const auto &account_management_action: json["account_management_actions_supported"]) {
        response.account_management_actions_supported.push_back(account_management_action.asString());
    }

    this->openid_configuration = response;

    co_return response;
}
