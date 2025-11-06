#include "trdp_manager.h"

#include "httplib.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

namespace {
std::string read_file(const std::filesystem::path &path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        return {};
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

std::string escape_json(const std::string &value) {
    std::ostringstream oss;
    for (const char c : value) {
        switch (c) {
        case '\\':
            oss << "\\\\";
            break;
        case '"':
            oss << "\\\"";
            break;
        case '\n':
            oss << "\\n";
            break;
        case '\r':
            oss << "\\r";
            break;
        case '\t':
            oss << "\\t";
            break;
        default:
            oss << c;
            break;
        }
    }
    return oss.str();
}

std::string to_json(const std::vector<TrdpIncomingMessage> &messages) {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < messages.size(); ++i) {
        const auto &msg = messages[i];
        if (i > 0) {
            oss << ",";
        }
        oss << "{"
            << "\"source_ip\":\"" << escape_json(msg.source_ip) << "\",";
        oss << "\"com_id\":\"" << escape_json(msg.com_id) << "\",";
        oss << "\"dataset_id\":\"" << escape_json(msg.dataset_id) << "\",";
        oss << "\"payload_hex\":\"" << escape_json(msg.payload_hex) << "\",";
        oss << "\"timestamp\":\"" << escape_json(msg.timestamp) << "\"";
        oss << "}";
    }
    oss << "]";
    return oss.str();
}

std::string json_message(const std::string &status,
                         const std::string &message,
                         const std::string &extra = "") {
    std::ostringstream oss;
    oss << "{\"status\":\"" << status << "\",\"message\":\"" << message << "\"";
    if (!extra.empty()) {
        oss << "," << extra;
    }
    oss << "}";
    return oss.str();
}
} // namespace

int main() {
    TrdpManager trdp_manager;

    httplib::Server server;

    const std::filesystem::path public_dir = std::filesystem::current_path() / "public";

    server.Get("/", [public_dir](const httplib::Request &, httplib::Response &res) {
        const auto index_path = public_dir / "index.html";
        std::string content = read_file(index_path);
        if (content.empty()) {
            res.status = 404;
            res.set_content("Missing index.html", "text/plain");
            return;
        }
        res.set_content(content, "text/html");
    });

    server.Get("/api/status", [&trdp_manager](const httplib::Request &, httplib::Response &res) {
        std::ostringstream extra;
        extra << "\"running\":" << (trdp_manager.is_running() ? "true" : "false")
              << ",\"payload\":\"" << escape_json(trdp_manager.outgoing_payload()) << "\"";
        res.set_content(json_message("ok", "status", extra.str()), "application/json");
    });

    server.Post("/api/start", [&trdp_manager](const httplib::Request &, httplib::Response &res) {
        if (trdp_manager.start()) {
            res.set_content(json_message("ok", "TRDP communication started"), "application/json");
        } else {
            res.status = 500;
            res.set_content(json_message("error", "Failed to start TRDP"), "application/json");
        }
    });

    server.Post("/api/stop", [&trdp_manager](const httplib::Request &, httplib::Response &res) {
        trdp_manager.stop();
        res.set_content(json_message("ok", "TRDP communication stopped"), "application/json");
    });

    server.Post("/api/upload_config",
                [&trdp_manager](const httplib::Request &req, httplib::Response &res) {
                    if (!req.is_multipart_form_data()) {
                        res.status = 400;
                        res.set_content(json_message("error", "Expected multipart form data"),
                                        "application/json");
                        return;
                    }

                    const auto &files = req.files;
                    auto it = files.find("config");
                    if (it == files.end()) {
                        res.status = 400;
                        res.set_content(json_message("error", "Missing config file"),
                                        "application/json");
                        return;
                    }

                    const std::string &xml_content = it->second.content;
                    if (!trdp_manager.load_configuration(xml_content)) {
                        res.status = 500;
                        res.set_content(json_message("error", "Failed to load configuration"),
                                        "application/json");
                        return;
                    }

                    res.set_content(json_message("ok", "Configuration loaded"), "application/json");
                });

    server.Post("/api/payload", [&trdp_manager](const httplib::Request &req, httplib::Response &res) {
        std::string payload = req.body;
        if (payload.empty()) {
            res.status = 400;
            res.set_content(json_message("error", "Payload is empty"), "application/json");
            return;
        }

        if (!trdp_manager.update_outgoing_payload(payload)) {
            res.status = 400;
            res.set_content(json_message("error", "Invalid payload"), "application/json");
            return;
        }
        res.set_content(json_message("ok", "Payload updated"), "application/json");
    });

    server.Get("/api/messages", [&trdp_manager](const httplib::Request &, httplib::Response &res) {
        auto messages = trdp_manager.consume_recent_messages();
        std::ostringstream extra;
        extra << "\"messages\":" << to_json(messages);
        res.set_content(json_message("ok", "messages", extra.str()), "application/json");
    });

    std::cout << "TRDP manager web UI running on http://0.0.0.0:8080" << std::endl;
    server.listen("0.0.0.0", 8080);
    return 0;
}
