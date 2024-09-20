#pragma once
#include "json.hpp"
#include "utils.hpp"

#include "cppcoro/task.hpp"
#include <curl/curl.h>
#include <cthash/sha2/sha256.hpp>


class BaseClient {
};

class LoggedInClient : public BaseClient {
    LoginResponse login_data;

public:
    explicit LoggedInClient(LoginResponse login_data) : login_data(std::move(login_data)) {
    }
};

class Client : public BaseClient {
    friend class ClientTest; // Declare the test class as a friend

public:
    ~Client() {
        curl_easy_cleanup(curl);
    }

private:
    CURL *curl = curl_easy_init();

    /**
     * \brief Fetches the well-known configuration from the specified homeserver.
     *
     * This function sends a request to the given homeserver to retrieve the well-known configuration.
     *
     * \param homeserver The URL of the homeserver from which to fetch the well-known configuration.
     * \return A cppcoro::task that resolves to a WellKnownResponse containing the well-known configuration.
     */
    [[nodiscard]] cppcoro::task<WellKnownResponse> fetch_wellknown(const std::string &homeserver) const;

    /**
     * \brief Fetches the authentication issuer information from the specified client-server endpoint.
     *
     * This function sends a request to the given client-server endpoint to retrieve the authentication issuer information.
     *
     * \param cs_endpoint The URL of the client-server endpoint from which to fetch the authentication issuer information.
     * \return A cppcoro::task that resolves to an AuthIssuerResponse containing the authentication issuer information.
     */
    [[nodiscard]] cppcoro::task<AuthIssuerResponse> fetch_auth_issuer(const std::string &cs_endpoint) const;

    /**
     * \brief Registers a client with the specified authentication endpoint (MSC2966).
     *
     * This function sends a registration request to the given authentication endpoint using the provided registration data.
     * It allows the client to be registered as an OAuth2 client on the OIDC server side, enabling the client to let people log in.
     *
     * \param auth_endpoint The URL of the authentication endpoint to register the client.
     * \param registration_data The data required for client registration.
     * \return A cppcoro::task that resolves to a ClientRegistrationResponse containing the registration result.
     */
    [[nodiscard]] cppcoro::task<ClientRegistrationResponse> register_client(const std::string &auth_endpoint,
                                                                            const ClientRegistrationData &
                                                                            registration_data) const;


    // ReSharper disable once CppMemberFunctionMayBeStatic
    // NOLINTNEXTLINE(*-convert-member-functions-to-static)
    [[nodiscard]] constexpr std::string generate_authorize_url(const std::string &auth_endpoint,
                                                               const ClientRegistrationResponse &auth_data,
                                                               const std::string &redirect_url,
                                                               const std::string &state,
                                                               const std::string &code_verifier) const {
        // URL encode the redirect URL
        const auto url_encoded_redirect_url = url_encode(redirect_url);

        // Calculate the code challenge from the code_verifier by doing `BASE64URL(SHA256(code_verifier))`
        const auto code_challenge = cthash::base64url_encode(cthash::simple<cthash::sha256>(code_verifier)).to_string();


        return auth_endpoint + "/authorize?response_type=code&response_mode=fragment&client_id=" +
               auth_data.client_id + "&redirect_uri=" + url_encoded_redirect_url +
               "&scope=urn%3Amatrix%3Aorg.matrix.msc2967.client%3Aapi%3A*%20urn%3Amatrix%3Aorg.matrix.msc2967.client%3Adevice%3AABCDEFGHIJKL&state="
               + state + "&code_challenge_method=S256" + "&code_challenge=" + code_challenge;
    }
};
