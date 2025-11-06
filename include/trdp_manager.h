#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

struct TrdpIncomingMessage {
    std::string source_ip;
    std::string com_id;
    std::string dataset_id;
    std::string payload_hex;
    std::string timestamp;
};

class TrdpManager {
  public:
    TrdpManager();
    ~TrdpManager();

    bool start();
    void stop();

    bool load_configuration(const std::string &xml_content);
    void update_outgoing_payload(const std::string &payload_hex);

    bool is_running() const { return running_; }
    std::string current_configuration() const;
    std::string outgoing_payload() const;

    std::vector<TrdpIncomingMessage> consume_recent_messages();

  private:
    void simulation_loop();

    mutable std::mutex mutex_;
    bool running_;
    std::string configuration_xml_;
    std::string outgoing_payload_hex_;

    std::thread simulation_thread_;
    std::atomic<bool> stop_simulation_;
    std::vector<TrdpIncomingMessage> message_queue_;
    uint64_t simulated_counter_;
};
