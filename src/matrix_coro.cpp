#include "matrix_coro.hpp"
#include "spdlog/spdlog.h"

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

cppcoro::task<AuthIssuerResponse> Client::fetch_auth_issuer(std::string cs_endpoint) const {
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

cppcoro::task<ClientRegistrationResponse> Client::register_client(std::string registration_endpoint,
                                                                  const ClientRegistrationData &registration_data)
const {
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    if (registration_endpoint.find("https://") == std::string::npos) {
        throw std::runtime_error("invalid registration endpoint");
    }

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, registration_endpoint.c_str());
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
    root["contacts"] = Json::arrayValue;
    for (const auto &contact: registration_data.contacts) {
        root["contacts"].append(contact);
    }

    // Convert the JSON to a string
    Json::StreamWriterBuilder writer;
    const std::string json_str = Json::writeString(writer, root);

    // Set the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str.c_str());

    // Set the Content-Type header
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to find registration information: " + std::string(curl_easy_strerror(res)));
    }

    Json::Value resp_root;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, resp_root); !parse_status) {
        throw std::runtime_error("failed to parse registration information");
    }
    ClientRegistrationResponse response;
    response.client_id = resp_root["client_id"].asString();
    response.client_id_issued_at = resp_root["client_id_issued_at"].asInt();
    co_return response;
}

cppcoro::task<TokenResponse> Client::exchange_code_for_token(std::string token_endpoint,
                                                             const std::string &code,
                                                             const std::string &code_verifier,
                                                             const std::string &client_id,
                                                             const std::string &redirect_url) const {
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }
    if (token_endpoint.find("https://") == std::string::npos) {
        throw std::runtime_error("invalid token_endpoint");
    }

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, token_endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    // Make it a POST request
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    // Url encode the redirect URL
    const auto url_encoded_redirect_url = url_encode(redirect_url);

    // Build the request body
    const std::string post_fields = "grant_type=authorization_code&code=" + code + "&redirect_uri=" +
                                    url_encoded_redirect_url +
                                    "&client_id=" + client_id + "&code_verifier=" + code_verifier;

    // Set the POST data
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_fields.c_str());

    // Set the Content-Type header
    curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);


    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error("failed to find exchange token information: " + std::string(curl_easy_strerror(res)));
    }

    Json::Value resp_root;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, resp_root); !parse_status) {
        throw std::runtime_error("failed to parse exchange token information");
    }

    TokenResponse response;
    response.access_token = resp_root["access_token"].asString();
    response.expires_in = resp_root["expires_in"].asInt();
    response.refresh_token = resp_root["refresh_token"].asString();
    response.token_type = resp_root["token_type"].asString();
    response.scope = resp_root["scope"].asString();

    co_return response;
}

cppcoro::task<OpenIDConfiguration> Client::fetch_openid_configuration(std::string auth_endpoint) const {
    if (!curl) {
        throw std::runtime_error("http client is not initialized");
    }

    if (auth_endpoint.find("https://") == std::string::npos || auth_endpoint.find("_matrix/client") != std::string::npos
        ||
        auth_endpoint.back() == '/') {
        throw std::runtime_error("invalid auth_endpoint");
    }

    const auto endpoint = auth_endpoint + "/.well-known/openid-configuration";

    std::string str_buffer;
    curl_easy_setopt(curl, CURLOPT_URL, endpoint.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &str_buffer);

    /* enable all supported built-in compressions */
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");

    //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

    if (const CURLcode res = curl_easy_perform(curl); res != CURLE_OK) {
        throw std::runtime_error(
            "failed to find openid configuration information: " + std::string(curl_easy_strerror(res)));
    }

    Json::Value root;
    Json::Reader reader;
    if (const bool parse_status = reader.parse(str_buffer, root); !parse_status) {
        throw std::runtime_error("failed to parse openid configuration information");
    }

    OpenIDConfiguration response;
    response.issuer = root["issuer"].asString();
    response.authorization_endpoint = root["authorization_endpoint"].asString();
    response.token_endpoint = root["token_endpoint"].asString();
    response.jwks_uri = root["jwks_uri"].asString();
    response.registration_endpoint = root["registration_endpoint"].asString();

    for (const auto &scope: root["scopes_supported"]) {
        response.scopes_supported.push_back(scope.asString());
    }
    for (const auto &response_type: root["response_types_supported"]) {
        response.response_types_supported.push_back(response_type.asString());
    }
    for (const auto &response_mode: root["response_modes_supported"]) {
        response.response_modes_supported.push_back(response_mode.asString());
    }
    for (const auto &grant_type: root["grant_types_supported"]) {
        response.grant_types_supported.push_back(grant_type.asString());
    }
    for (const auto &token_endpoint_auth_method: root["token_endpoint_auth_methods_supported"]) {
        response.token_endpoint_auth_methods_supported.push_back(token_endpoint_auth_method.asString());
    }
    for (const auto &token_endpoint_auth_signing_alg: root["token_endpoint_auth_signing_alg_values_supported"]) {
        response.token_endpoint_auth_signing_alg_values_supported.push_back(token_endpoint_auth_signing_alg.asString());
    }
    response.revocation_endpoint = root["revocation_endpoint"].asString();
    for (const auto &revocation_endpoint_auth_method: root["revocation_endpoint_auth_methods_supported"]) {
        response.revocation_endpoint_auth_methods_supported.push_back(revocation_endpoint_auth_method.asString());
    }
    for (const auto &revocation_endpoint_auth_signing_alg: root[
             "revocation_endpoint_auth_signing_alg_values_supported"]) {
        response.revocation_endpoint_auth_signing_alg_values_supported.push_back(
            revocation_endpoint_auth_signing_alg.asString());
    }
    response.introspection_endpoint = root["introspection_endpoint"].asString();
    for (const auto &introspection_endpoint_auth_method: root["introspection_endpoint_auth_methods_supported"]) {
        response.introspection_endpoint_auth_methods_supported.push_back(introspection_endpoint_auth_method.asString());
    }
    for (const auto &introspection_endpoint_auth_signing_alg: root[
             "introspection_endpoint_auth_signing_alg_values_supported"]) {
        response.introspection_endpoint_auth_signing_alg_values_supported.push_back(
            introspection_endpoint_auth_signing_alg.asString());
    }
    for (const auto &code_challenge_method: root["code_challenge_methods_supported"]) {
        response.code_challenge_methods_supported.push_back(code_challenge_method.asString());
    }
    response.userinfo_endpoint = root["userinfo_endpoint"].asString();
    for (const auto &subject_type: root["subject_types_supported"]) {
        response.subject_types_supported.push_back(subject_type.asString());
    }
    for (const auto &id_token_signing_alg: root["id_token_signing_alg_values_supported"]) {
        response.id_token_signing_alg_values_supported.push_back(id_token_signing_alg.asString());
    }
    for (const auto &userinfo_signing_alg: root["userinfo_signing_alg_values_supported"]) {
        response.userinfo_signing_alg_values_supported.push_back(userinfo_signing_alg.asString());
    }
    for (const auto &display_value: root["display_values_supported"]) {
        response.display_values_supported.push_back(display_value.asString());
    }
    for (const auto &claim_type: root["claim_types_supported"]) {
        response.claim_types_supported.push_back(claim_type.asString());
    }
    for (const auto &claim: root["claims_supported"]) {
        response.claims_supported.push_back(claim.asString());
    }
    response.claims_parameter_supported = root["claims_parameter_supported"].asBool();
    response.request_parameter_supported = root["request_parameter_supported"].asBool();
    response.request_uri_parameter_supported = root["request_uri_parameter_supported"].asBool();
    for (const auto &prompt_value: root["prompt_values_supported"]) {
        response.prompt_values_supported.push_back(prompt_value.asString());
    }
    response.device_authorization_endpoint = root["device_authorization_endpoint"].asString();
    response.org_matrix_matrix_authentication_service_graphql_endpoint = root[
        "org.matrix.matrix_authentication_service_graphql_endpoint"].asString();
    response.account_management_uri = root["account_management_uri"].asString();
    for (const auto &account_management_action: root["account_management_actions_supported"]) {
        response.account_management_actions_supported.push_back(account_management_action.asString());
    }

    co_return response;
}
