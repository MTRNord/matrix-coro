#include <iostream>

#include "matrix_coro.hpp"
#include <catch2/catch_test_macros.hpp>
#include "spdlog/spdlog.h"

#include "cppcoro/sync_wait.hpp"

class ClientTest {
public:
    static cppcoro::task<WellKnownResponse> test_fetch_wellknown(const Client &client, const std::string &homeserver) {
        return client.fetch_wellknown(homeserver);
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
            const Client client;
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
                const Client client;
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
                const Client client;
                REQUIRE_THROWS_AS(
                    sync_wait(ClientTest::test_fetch_wellknown(client,"https://example.com/invalid-json")),
                    std::runtime_error);
            }
        }
    }
}
