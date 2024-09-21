#include <iostream>

#include "matrix_coro.hpp"
#include <catch2/catch_test_macros.hpp>
#include "spdlog/spdlog.h"

#include "cppcoro/sync_wait.hpp"

class ClientTest {
public:
    static cppcoro::task<WellKnownResponse> test_fetch_wellknown(Client &client, const std::string &homeserver) {
        return client.fetch_wellknown(homeserver);
    }

    static cppcoro::task<AuthIssuerResponse> test_fetch_auth_issuer(Client &client,
                                                                    const std::string &cs_endpoint) {
        return client.fetch_auth_issuer(cs_endpoint);
    }

    static cppcoro::task<ClientRegistrationResponse> test_register_client(Client &client,
                                                                          const std::string &registration_endpoint,
                                                                          const ClientRegistrationData &
                                                                          registration_data) {
        return client.register_client(registration_endpoint, registration_data);
    }

    static std::string test_generate_authorize_url(Client &client,
                                                   const std::string &auth_endpoint,
                                                   const ClientRegistrationResponse &auth_data,
                                                   const std::string &redirect_url,
                                                   const std::string &state,
                                                   const std::string &code_verifier) {
        return client.generate_authorize_url(auth_endpoint, auth_data, redirect_url, state, code_verifier);
    }

    static cppcoro::task<OpenIDConfiguration> fetch_openid_configuration(Client &client,
                                                                         const std::string &auth_endpoint) {
        return client.fetch_openid_configuration(auth_endpoint);
    }

    static cppcoro::task<TokenResponse> exchange_code_for_token(const Client &client,
                                                                const std::string &token_endpoint,
                                                                const std::string &client_id,
                                                                const std::string &code,
                                                                const std::string &redirect_uri,
                                                                const std::string &code_verifier) {
        return client.exchange_code_for_token(token_endpoint, code, code_verifier, client_id, redirect_uri);
    }
};

void initLogging() {
    spdlog::set_level(spdlog::level::debug);
    spdlog::set_pattern("[%H:%M:%S %z] [%^%L%$] [thread %t] %v");
}


SCENARIO("fetch_wellknown can find and parse well-known at matrix.org") {
    initLogging();
    GIVEN("A Client instance") {
        WHEN("fetch_wellknown is called with matrix.org") {
            Client client;
            auto task = ClientTest::test_fetch_wellknown(client, "matrix.org");
            auto [homeserver, identity_server, raw] = sync_wait(task);
            THEN("A valid WellKnownResponse should be returned") {
                REQUIRE(homeserver == "https://matrix-client.matrix.org");
                REQUIRE(identity_server == "https://vector.im");
            }
        }
    }
}

SCENARIO("fetch_wellknown throws runtime_error if curl_easy_perform fails") {
    initLogging();
    GIVEN("A Client instance with an invalid URL") {
        WHEN("fetch_wellknown is called with an invalid URL") {
            THEN("A runtime_error should be thrown") {
                Client client;
                REQUIRE_THROWS_AS(sync_wait(ClientTest::test_fetch_wellknown(client,"invalid_url")),
                                  std::runtime_error);
            }
        }
    }
}

SCENARIO("fetch_wellknown throws runtime_error if JSON parsing fails") {
    initLogging();
    GIVEN("A Client instance with a URL returning invalid JSON") {
        WHEN("fetch_wellknown is called with a URL returning invalid JSON") {
            THEN("A runtime_error should be thrown") {
                Client client;
                REQUIRE_THROWS_AS(
                    sync_wait(ClientTest::test_fetch_wellknown(client,"https://example.com/invalid-json")),
                    std::runtime_error);
            }
        }
    }
}

SCENARIO("fetch_auth_issuer can find and parse auth issuer at https://synapse-oidc.element.dev") {
    initLogging();
    GIVEN("A Client instance") {
        WHEN("fetch_auth_issuer is called with https://synapse-oidc.element.dev") {
            Client client;
            auto task = ClientTest::test_fetch_auth_issuer(client, "https://synapse-oidc.element.dev");
            auto [issuer] = sync_wait(task);
            THEN("A valid AuthIssuerResponse should be returned") {
                REQUIRE(issuer == "https://auth-oidc.element.dev/");
            }
        }
    }
}

SCENARIO("fetch_auth_issuer throws runtime_error if curl_easy_perform fails") {
    initLogging();
    GIVEN("A Client instance with an invalid URL") {
        WHEN("fetch_auth_issuer is called with an invalid URL") {
            THEN("A runtime_error should be thrown") {
                Client client;
                REQUIRE_THROWS_AS(sync_wait(ClientTest::test_fetch_auth_issuer(client,"invalid_url")),
                                  std::runtime_error);
            }
        }
    }
}

SCENARIO("fetch_auth_issuer throws runtime_error if JSON parsing fails") {
    initLogging();
    GIVEN("A Client instance with a URL returning invalid JSON") {
        WHEN("fetch_auth_issuer is called with a URL returning invalid JSON") {
            THEN("A runtime_error should be thrown") {
                Client client;
                REQUIRE_THROWS_AS(
                    sync_wait(ClientTest::test_fetch_auth_issuer(client,"https://example.com/invalid-json")),
                    std::runtime_error);
            }
        }
    }
}

SCENARIO("register_client can register a client at https://synapse-oidc.element.dev") {
    initLogging();
    GIVEN("A Client instance") {
        WHEN("register_client is called with https://synapse-oidc.element.dev") {
            Client client;
            ClientRegistrationData registration_data;
            registration_data.application_type = "web";
            registration_data.client_name = "Test Client";
            registration_data.client_uri = "https://example.com";
            registration_data.token_endpoint_auth_method = "none";
            registration_data.redirect_uris = {"https://example.com"};
            registration_data.response_types = {"code"};
            registration_data.grant_types = {"authorization_code", "refresh_token"};
            registration_data.contacts = {"mailto:hello@example.com"};
            auto task = ClientTest::test_register_client(client, "https://auth-oidc.element.dev/oauth2/registration",
                                                         registration_data);
            auto [client_id, client_id_issued_at] = sync_wait(task);
            THEN("A valid ClientRegistrationResponse should be returned") {
                REQUIRE(!client_id.empty());
                REQUIRE(client_id_issued_at > 0);
            }
        }
    }
}

SCENARIO("register_client throws runtime_error if curl_easy_perform fails") {
    initLogging();
    GIVEN("A Client instance with an invalid URL") {
        WHEN("register_client is called with an invalid URL") {
            THEN("A runtime_error should be thrown") {
                Client client;
                ClientRegistrationData registration_data;
                registration_data.application_type = "web";
                registration_data.client_name = "Test Client";
                registration_data.client_uri = "https://example.com";
                registration_data.token_endpoint_auth_method = "none";
                registration_data.redirect_uris = {"https://example.com"};
                registration_data.response_types = {"code"};
                registration_data.grant_types = {"authorization_code", "refresh_token"};
                registration_data.contacts = {"mailto:hello@example.com"};
                REQUIRE_THROWS_AS(sync_wait(ClientTest::test_register_client(client,"invalid_url", registration_data)),
                                  std::runtime_error);
            }
        }
    }
}

SCENARIO("register_client throws runtime_error if JSON parsing fails") {
    initLogging();
    GIVEN("A Client instance with a URL returning invalid JSON") {
        WHEN("register_client is called with a URL returning invalid JSON") {
            THEN("A runtime_error should be thrown") {
                Client client;
                ClientRegistrationData registration_data;
                registration_data.application_type = "web";
                registration_data.client_name = "Test Client";
                registration_data.client_uri = "https://example.com";
                registration_data.token_endpoint_auth_method = "none";
                registration_data.redirect_uris = {"https://example.com"};
                registration_data.response_types = {"code"};
                registration_data.grant_types = {"authorization_code", "refresh_token"};
                registration_data.contacts = {"mailto:hello@example.com"};
                REQUIRE_THROWS_AS(
                    sync_wait(ClientTest::test_register_client(client,"https://example.com/invalid-json",
                        registration_data)),
                    std::runtime_error);
            }
        }
    }
}

SCENARIO("generate_authorize_url can generate a valid authorize URL") {
    initLogging();
    GIVEN("A Client") {
        WHEN("generate_authorize_url is called") {
            Client client;
            ClientRegistrationResponse auth_data;
            auth_data.client_id = "test_client_id";
            auth_data.client_id_issued_at = 1630000000;
            std::string redirect_url = "https://example.com";
            std::string state = "test_state";
            std::string code_verifier = "test_code_verifier";
            auto authorize_url = ClientTest::test_generate_authorize_url(
                client, "https://auth-oidc.element.dev/authorize",
                auth_data, redirect_url, state, code_verifier);
            THEN("A valid authorize URL should be returned") {
                REQUIRE(
                    authorize_url ==
                    "https://auth-oidc.element.dev/authorize?response_type=code&response_mode=fragment&client_id=test_client_id&redirect_uri=https%3A%2F%2Fexample.com&scope=urn%3Amatrix%3Aorg.matrix.msc2967.client%3Aapi%3A*%20urn%3Amatrix%3Aorg.matrix.msc2967.client%3Adevice%3AABCDEFGHIJKL&state=test_state&code_challenge_method=S256&code_challenge="
                    + cthash::base64url_encode(cthash::simple<cthash::sha256>(code_verifier)).to_string());
            }
        }
    }
}

// Fetch openid configuration
SCENARIO("fetch_openid_configuration can find and parse openid configuration at https://auth-oidc.element.dev") {
    initLogging();
    GIVEN("A Client instance") {
        WHEN("fetch_openid_configuration is called with https://auth-oidc.element.dev") {
            Client client;
            auto task = ClientTest::fetch_openid_configuration(client, "https://auth-oidc.element.dev");
            auto resp = sync_wait(task);
            THEN("A valid OpenIDConfiguration should be returned") {
                REQUIRE(resp.issuer == "https://auth-oidc.element.dev/");
                REQUIRE(resp.authorization_endpoint == "https://auth-oidc.element.dev/authorize");
                REQUIRE(resp.token_endpoint == "https://auth-oidc.element.dev/oauth2/token");
                REQUIRE(resp.jwks_uri == "https://auth-oidc.element.dev/oauth2/keys.json");
                REQUIRE(resp.registration_endpoint == "https://auth-oidc.element.dev/oauth2/registration");
                REQUIRE(resp.revocation_endpoint == "https://auth-oidc.element.dev/oauth2/revoke");
                REQUIRE(resp.introspection_endpoint == "https://auth-oidc.element.dev/oauth2/introspect");
                REQUIRE(resp.userinfo_endpoint == "https://auth-oidc.element.dev/oauth2/userinfo");
                REQUIRE(resp.device_authorization_endpoint == "https://auth-oidc.element.dev/oauth2/device");
                REQUIRE(resp.account_management_uri == "https://auth-oidc.element.dev/account/");
            }
        }
    }
}

SCENARIO("fetch_openid_configuration throws runtime_error if curl_easy_perform fails") {
    initLogging();
    GIVEN("A Client instance with an invalid URL") {
        WHEN("fetch_openid_configuration is called with an invalid URL") {
            THEN("A runtime_error should be thrown") {
                Client client;
                REQUIRE_THROWS_AS(sync_wait(ClientTest::fetch_openid_configuration(client,"invalid_url")),
                                  std::runtime_error);
            }
        }
    }
}

SCENARIO("fetch_openid_configuration throws runtime_error if JSON parsing fails") {
    initLogging();
    GIVEN("A Client instance with a URL returning invalid JSON") {
        WHEN("fetch_openid_configuration is called with a URL returning invalid JSON") {
            THEN("A runtime_error should be thrown") {
                Client client;
                REQUIRE_THROWS_AS(
                    sync_wait(ClientTest::fetch_openid_configuration(client,"https://example.com/invalid-json")),
                    std::runtime_error);
            }
        }
    }
}
