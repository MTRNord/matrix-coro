#include <spdlog/spdlog.h>

#include "matrix_coro.hpp"
#include "cppcoro/sync_wait.hpp"

int main() {
    spdlog::set_level(spdlog::level::info);
    spdlog::set_pattern("[%H:%M:%S %z] [%^%L%$] [thread %t] %v");

    Client client;

    const auto homeserver = "https://synapse-oidc.element.dev";
    auto redirect_url = "https://areweoidcyet.com/client-implementation-guide/callback";
    const auto state = "state";
    const auto code_verifier =
            "ahlae7FuMahCeeseip6Shooqu6aefai5xoocea5gav2";
    ClientRegistrationData registration_data;
    registration_data.application_type = "web";
    registration_data.client_name = "Test";
    registration_data.client_uri = "https://areweoidcyet.com/";
    registration_data.token_endpoint_auth_method = "none";
    registration_data.redirect_uris = {redirect_url};
    registration_data.response_types = {"code"};
    registration_data.grant_types = {"authorization_code", "refresh_token"};
    registration_data.contacts = {"mailto:hello@localhost"};

    auto auth_url_task = client.get_auth_url(homeserver, redirect_url, state, code_verifier, registration_data);

    auto auth_url = sync_wait(auth_url_task);

    spdlog::info("Please login via the Auth URL: {}", auth_url);

    // Wait for the user to paste the code here
    std::string code;
    spdlog::info("Please paste the code here: ");
    std::cin >> code;

    const auto logged_in_client = sync_wait(client.exchange_token(code, redirect_url));

    const auto whoami = sync_wait(logged_in_client.whoami());

    spdlog::info("User ID: {}", whoami.user_id);

    return 0;
}
