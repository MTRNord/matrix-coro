#pragma once
#include "json.hpp"
#include "utils.hpp"

#include "cppcoro/task.hpp"
#include <cthash/sha2/sha256.hpp>
#include <spdlog/spdlog.h>


class BaseClient {
public:
    std::string user_agent = "MatrixCoro SDK/0.1.0";
};

class LoggedInClient : public BaseClient {
    TokenResponse token_data;
    WellKnownResponse well_known;

    [[nodiscard]] cppcoro::task<Json::Value> get(const std::string &url) const;

public:
    LoggedInClient(TokenResponse token_data, WellKnownResponse well_known): token_data(std::move(token_data)),
                                                                            well_known(std::move(well_known)) {
    }

    [[nodiscard]] cppcoro::task<WhoamiResponse> whoami() const;
};

class Client : public BaseClient {
    friend class ClientTest; // Declare the test class as a friend

public:
    [[nodiscard]] cppcoro::task<std::string> get_auth_url(std::string homeserver, std::string redirect_url,
                                                          std::string state, std::string code_verifier,
                                                          const ClientRegistrationData &registration_data);

    [[nodiscard]] cppcoro::task<LoggedInClient> exchange_token(const std::string &code,
                                                               const std::string &redirect_url) const;

private:
    WellKnownResponse well_known;
    AuthIssuerResponse auth_issuer;
    ClientRegistrationResponse client_registration;
    OpenIDConfiguration openid_configuration;
    std::string state;
    std::string code_verifier;

    [[nodiscard]] cppcoro::task<Json::Value> get(const std::string &url) const;

    [[nodiscard]] cppcoro::task<Json::Value> post(const std::string &url, const std::string &data,
                                                  bool form_data = false) const;

    /**
     * \brief Fetches the well-known configuration from the specified homeserver.
     *
     * This function sends a request to the given homeserver to retrieve the well-known configuration.
     *
     * \param homeserver The URL of the homeserver from which to fetch the well-known configuration.
     * \return A cppcoro::task that resolves to a WellKnownResponse containing the well-known configuration.
     */
    [[nodiscard]] cppcoro::task<WellKnownResponse> fetch_wellknown(std::string homeserver);

    /**
     * \brief Fetches the authentication issuer information from the specified client-server endpoint.
     *
     * This function sends a request to the given client-server endpoint to retrieve the authentication issuer information.
     *
     * \param cs_endpoint The URL of the client-server endpoint from which to fetch the authentication issuer information.
     * \return A cppcoro::task that resolves to an AuthIssuerResponse containing the authentication issuer information.
     */
    [[nodiscard]] cppcoro::task<AuthIssuerResponse> fetch_auth_issuer(std::string cs_endpoint);

    /**
     * \brief Registers a client with the specified authentication endpoint (MSC2966).
     *
     * This function sends a registration request to the given authentication endpoint using the provided registration data.
     * It allows the client to be registered as an OAuth2 client on the OIDC server side, enabling the client to let people log in.
     *
     * \param registration_endpoint The URL of the registration endpoint to register the client which can be optained from the openid-configuration.
     * \param registration_data The data required for client registration.
     * \return A cppcoro::task that resolves to a ClientRegistrationResponse containing the registration result.
     */
    [[nodiscard]] cppcoro::task<ClientRegistrationResponse> register_client(std::string registration_endpoint,
                                                                            const ClientRegistrationData &
                                                                            registration_data);


    // ReSharper disable once CppMemberFunctionMayBeStatic
    // NOLINTNEXTLINE(*-convert-member-functions-to-static)
    [[nodiscard]] constexpr std::string generate_authorize_url(const std::string &auth_endpoint,
                                                               const ClientRegistrationResponse &auth_data,
                                                               const std::string &redirect_url,
                                                               const std::string &state,
                                                               const std::string &code_verifier) const {
        spdlog::debug("Code verifier: {}", code_verifier);
        // URL encode the redirect URL
        const auto url_encoded_redirect_url = url_encode(redirect_url);

        // Calculate the code challenge from the code_verifier by doing `BASE64URL(SHA256(code_verifier))`
        const auto sha256_code_verifier = cthash::simple<cthash::sha256>(code_verifier);
        const auto code_challenge = cthash::base64url_encode(sha256_code_verifier).to_string();

        return auth_endpoint + "?response_type=code&response_mode=fragment&client_id=" +
               auth_data.client_id + "&redirect_uri=" + url_encoded_redirect_url +
               "&scope=urn%3Amatrix%3Aorg.matrix.msc2967.client%3Aapi%3A*%20urn%3Amatrix%3Aorg.matrix.msc2967.client%3Adevice%3AABCDEFGHIJKL&state="
               + state + "&code_challenge_method=S256" + "&code_challenge=" + code_challenge;
    }

    [[nodiscard]] cppcoro::task<TokenResponse> exchange_code_for_token(
        std::string token_endpoint,
        const std::string &code,
        const std::string &code_verifier,
        const std::string &client_id,
        const std::string &redirect_url) const;

    [[nodiscard]] cppcoro::task<OpenIDConfiguration> fetch_openid_configuration(
        std::string auth_endpoint);
};
