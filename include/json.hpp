#pragma once
#include <optional>

#include <json/json.h>

struct WellKnownResponse {
    std::string homeserver;
    std::string identity_server;
    Json::Value raw;
};

struct LoginResponse {
    std::string access_token;
    std::string device_id;
    std::optional<int> expires_in_ms;
    std::string home_server;
    std::optional<std::string> refresh_token;
    std::string user_id;
    WellKnownResponse well_known;
};

struct AuthIssuerResponse {
    std::string issuer;
};

struct OpenIDConfiguration {
    std::string issuer;
    std::string authorization_endpoint;
    std::string token_endpoint;
    std::string jwks_uri;
    std::string registration_endpoint;
    std::vector<std::string> scopes_supported;
    std::vector<std::string> response_types_supported;
    std::vector<std::string> response_modes_supported;
    std::vector<std::string> grant_types_supported;
    std::vector<std::string> token_endpoint_auth_methods_supported;
    std::vector<std::string> token_endpoint_auth_signing_alg_values_supported;
    std::string revocation_endpoint;
    std::vector<std::string> revocation_endpoint_auth_methods_supported;
    std::vector<std::string> revocation_endpoint_auth_signing_alg_values_supported;
    std::string introspection_endpoint;
    std::vector<std::string> introspection_endpoint_auth_methods_supported;
    std::vector<std::string> introspection_endpoint_auth_signing_alg_values_supported;
    std::vector<std::string> code_challenge_methods_supported;
    std::string userinfo_endpoint;
    std::vector<std::string> subject_types_supported;
    std::vector<std::string> id_token_signing_alg_values_supported;
    std::vector<std::string> userinfo_signing_alg_values_supported;
    std::vector<std::string> display_values_supported;
    std::vector<std::string> claim_types_supported;
    std::vector<std::string> claims_supported;
    bool claims_parameter_supported;
    bool request_parameter_supported;
    bool request_uri_parameter_supported;
    std::vector<std::string> prompt_values_supported;
    std::string device_authorization_endpoint;
    std::string org_matrix_matrix_authentication_service_graphql_endpoint;
    std::string account_management_uri;
    std::vector<std::string> account_management_actions_supported;
};

struct ClientRegistrationData {
    std::string application_type;
    std::string client_name;
    std::string client_uri;
    std::string token_endpoint_auth_method;
    std::vector<std::string> redirect_uris;
    std::vector<std::string> response_types;
    std::vector<std::string> grant_types;
};

struct ClientRegistrationResponse {
    std::string client_id;
    int client_id_issued_at;
};
