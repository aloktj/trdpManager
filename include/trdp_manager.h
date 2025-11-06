#pragma once

#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>
#include <cstdint>

#if !__has_include(<trdp_if_light.h>)
#error "TCNopen TRDP development headers are required"
#endif

extern "C" {
#include <trdp_if_light.h>
}

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
    bool update_outgoing_payload(const std::string &payload_hex);

    bool is_running() const { return running_; }
    std::string current_configuration() const;
    std::string outgoing_payload() const;

    std::vector<TrdpIncomingMessage> consume_recent_messages();

  private:
    static void pd_receive_callback(void *pRefCon,
                                    TRDP_APP_SESSION_T appHandle,
                                    const TRDP_PD_INFO_T *pPdInfo,
                                    const UINT8 *pData,
                                    UINT32 dataSize);

    static void log_callback(void *pRefCon,
                             TRDP_LOG_T category,
                             const CHAR8 *pTime,
                             const CHAR8 *pFile,
                             UINT16 line,
                             const CHAR8 *pMsg);

    void handle_pd_message(const TRDP_PD_INFO_T *pPdInfo,
                           const UINT8 *pData,
                           UINT32 dataSize);
    bool open_session_locked();
    void close_session_locked();
    bool configure_publication_locked();
    bool configure_subscription_locked();
    void process_loop();

    mutable std::mutex mutex_;
    bool running_;
    bool session_open_;
    std::string configuration_xml_;
    std::string outgoing_payload_hex_;

    std::thread process_thread_;
    std::atomic<bool> terminate_requested_;
    std::vector<TrdpIncomingMessage> message_queue_;

    TRDP_APP_SESSION_T app_handle_;
    TRDP_SUB_T subscriber_handle_;
    TRDP_PUB_T publisher_handle_;

    struct PublisherConfig {
        TRDP_COMID_T com_id;
        TRDP_DATASET_ID_T dataset_id;
        TRDP_IP_ADDR_T dest_ip;
        uint32_t cycle_time_us;
        uint32_t topo_counter;
        uint32_t reply_timeout;
        uint16_t qos;
        uint32_t dataset_size;
    };

    struct SubscriberConfig {
        TRDP_COMID_T com_id;
        TRDP_DATASET_ID_T dataset_id;
        uint32_t timeout_us;
        TRDP_IP_ADDR_T src_ip;
    };

    std::optional<PublisherConfig> publisher_config_;
    std::optional<SubscriberConfig> subscriber_config_;

    std::vector<uint8_t> outgoing_payload_;
};
