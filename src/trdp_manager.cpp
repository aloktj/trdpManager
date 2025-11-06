#include "trdp_manager.h"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <utility>

namespace {
std::string current_timestamp() {
    using clock = std::chrono::system_clock;
    const auto now = clock::now();
    const auto time = clock::to_time_t(now);
    std::tm tm = *std::gmtime(&time);

    std::ostringstream oss;
    oss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return oss.str();
}
}

TrdpManager::TrdpManager()
    : running_(false),
      outgoing_payload_hex_("00000000"),
      stop_simulation_(false),
      simulated_counter_(0) {}

TrdpManager::~TrdpManager() { stop(); }

bool TrdpManager::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
        return true;
    }

    running_ = true;
    stop_simulation_ = false;
    simulation_thread_ = std::thread(&TrdpManager::simulation_loop, this);
    return true;
}

void TrdpManager::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
        stop_simulation_ = true;
    }

    if (simulation_thread_.joinable()) {
        simulation_thread_.join();
    }
}

bool TrdpManager::load_configuration(const std::string &xml_content) {
    std::lock_guard<std::mutex> lock(mutex_);
    configuration_xml_ = xml_content;
    // TODO: Integrate with real TRDP stack configuration loader.
    return true;
}

void TrdpManager::update_outgoing_payload(const std::string &payload_hex) {
    std::lock_guard<std::mutex> lock(mutex_);
    outgoing_payload_hex_ = payload_hex;
    // TODO: Push payload to TRDP stack once integrated.
}

std::string TrdpManager::current_configuration() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return configuration_xml_;
}

std::string TrdpManager::outgoing_payload() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return outgoing_payload_hex_;
}

std::vector<TrdpIncomingMessage> TrdpManager::consume_recent_messages() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<TrdpIncomingMessage> messages;
    messages.swap(message_queue_);
    return messages;
}

void TrdpManager::simulation_loop() {
    using namespace std::chrono_literals;
    while (!stop_simulation_.load()) {
        std::this_thread::sleep_for(2s);

        TrdpIncomingMessage message;
        message.source_ip = "192.168.0.1";
        message.com_id = "0x100";
        message.dataset_id = "0x01";
        message.timestamp = current_timestamp();
        message.payload_hex = outgoing_payload_hex_;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            message.payload_hex = outgoing_payload_hex_;
            simulated_counter_++;
            std::ostringstream ds;
            ds << "0x" << std::hex << (simulated_counter_ % 0xFF);
            message.dataset_id = ds.str();
            message_queue_.push_back(message);
        }
    }
}
