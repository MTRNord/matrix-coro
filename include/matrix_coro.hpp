#pragma once
#include <future>
#include <optional>

#include "cppcoro/task.hpp"
#include <curl/curl.h>
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

struct PasswordLoginData {
    std::string homeserver;
    std::string mxid;
    std::string password;
    std::optional<std::string> initial_device_display_name;
};

class BaseClient {
};

class LoggedInClient : public BaseClient {
private:
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

    cppcoro::task<LoggedInClient> password_login(PasswordLoginData data) const {
        auto well_known_data = co_await fetch_wellknown(data.homeserver);
        co_return LoggedInClient(LoginResponse{});
    }

private:
    CURL *curl = curl_easy_init();

    cppcoro::task<WellKnownResponse> fetch_wellknown(const std::string &homeserver) const;
};

