#include "trdp_manager.h"

#include "tinyxml2.h"

#include <arpa/inet.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <utility>

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

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

std::string ip_to_string(TRDP_IP_ADDR_T address) {
    struct in_addr addr {};
    addr.s_addr = address;
    char buffer[INET_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET, &addr, buffer, sizeof(buffer)) == nullptr) {
        return "0.0.0.0";
    }
    return std::string(buffer);
}

std::string bytes_to_hex(const std::vector<uint8_t> &bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : bytes) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

bool hex_char_to_value(char c, uint8_t &value) {
    if (c >= '0' && c <= '9') {
        value = static_cast<uint8_t>(c - '0');
        return true;
    }
    if (c >= 'a' && c <= 'f') {
        value = static_cast<uint8_t>(10 + c - 'a');
        return true;
    }
    if (c >= 'A' && c <= 'F') {
        value = static_cast<uint8_t>(10 + c - 'A');
        return true;
    }
    return false;
}

bool hex_to_bytes(const std::string &hex, std::vector<uint8_t> &output) {
    if (hex.size() % 2 != 0) {
        return false;
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (size_t i = 0; i < hex.size(); i += 2) {
        uint8_t high = 0;
        uint8_t low = 0;
        if (!hex_char_to_value(hex[i], high) || !hex_char_to_value(hex[i + 1], low)) {
            return false;
        }
        bytes.push_back(static_cast<uint8_t>((high << 4) | low));
    }

    output = std::move(bytes);
    return true;
}

uint32_t parse_uint32(const char *value, uint32_t default_value) {
    if (value == nullptr) {
        return default_value;
    }
    char *end = nullptr;
    const uint32_t parsed = static_cast<uint32_t>(std::strtoul(value, &end, 0));
    if (end == value) {
        return default_value;
    }
    return parsed;
}

TRDP_IP_ADDR_T parse_ip_address(const char *value, TRDP_IP_ADDR_T default_value) {
    if (value == nullptr) {
        return default_value;
    }
    struct in_addr addr {};
    if (inet_aton(value, &addr) == 0) {
        return default_value;
    }
    return addr.s_addr;
}

} // namespace

TrdpManager::TrdpManager()
    : running_(false),
      session_open_(false),
      terminate_requested_(false),
      app_handle_(nullptr),
      subscriber_handle_(nullptr),
      publisher_handle_(nullptr) {}

TrdpManager::~TrdpManager() {
    stop();
}

bool TrdpManager::start() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
        return true;
    }

    if (!publisher_config_ && !subscriber_config_) {
        std::cerr << "TRDP start requested without configuration" << std::endl;
        return false;
    }

    if (!open_session_locked()) {
        return false;
    }

    if (subscriber_config_ && !configure_subscription_locked()) {
        close_session_locked();
        return false;
    }

    if (publisher_config_) {
        if (outgoing_payload_.empty() && publisher_config_->dataset_size > 0U) {
            outgoing_payload_.assign(publisher_config_->dataset_size, 0U);
            outgoing_payload_hex_ = bytes_to_hex(outgoing_payload_);
        }
        if (!configure_publication_locked()) {
            close_session_locked();
            return false;
        }
    }

    terminate_requested_.store(false);
    running_ = true;
    process_thread_ = std::thread(&TrdpManager::process_loop, this);
    return true;
}

void TrdpManager::stop() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            return;
        }
        running_ = false;
        terminate_requested_.store(true);
    }

    if (process_thread_.joinable()) {
        process_thread_.join();
    }

    std::lock_guard<std::mutex> lock(mutex_);
    close_session_locked();
}

bool TrdpManager::load_configuration(const std::string &xml_content) {
    stop();

    tinyxml2::XMLDocument doc;
    const auto parse_result = doc.Parse(xml_content.c_str(), xml_content.size());
    if (parse_result != tinyxml2::XML_SUCCESS) {
        std::cerr << "Failed to parse TRDP XML configuration: " << doc.ErrorStr() << std::endl;
        return false;
    }

    const tinyxml2::XMLElement *root = doc.RootElement();
    if (root == nullptr) {
        std::cerr << "TRDP XML configuration is empty" << std::endl;
        return false;
    }

    std::optional<PublisherConfig> publisher_config;
    std::optional<SubscriberConfig> subscriber_config;

    for (const tinyxml2::XMLElement *element = root->FirstChildElement(); element != nullptr;
         element = element->NextSiblingElement()) {
        const std::string name = element->Name() ? element->Name() : "";
        if (name == "Publisher") {
            PublisherConfig config{};
            config.com_id = static_cast<TRDP_COMID_T>(parse_uint32(element->Attribute("comId"), 0U));
            config.dataset_id = static_cast<TRDP_DATASET_ID_T>(parse_uint32(element->Attribute("datasetId"), 0U));
            config.dest_ip = parse_ip_address(element->Attribute("destIp"), 0U);
            config.cycle_time_us = parse_uint32(element->Attribute("cycle"), 1000000U);
            config.topo_counter = parse_uint32(element->Attribute("topoCount"), 0U);
            config.reply_timeout = parse_uint32(element->Attribute("replyTimeout"), 0U);
            config.qos = static_cast<uint16_t>(parse_uint32(element->Attribute("qos"), 0U));
            config.dataset_size = parse_uint32(element->Attribute("datasetSize"), 0U);

            if (config.com_id == 0U) {
                std::cerr << "Publisher element missing comId" << std::endl;
                return false;
            }
            publisher_config = config;
        } else if (name == "Subscriber") {
            SubscriberConfig config{};
            config.com_id = static_cast<TRDP_COMID_T>(parse_uint32(element->Attribute("comId"), 0U));
            config.dataset_id = static_cast<TRDP_DATASET_ID_T>(parse_uint32(element->Attribute("datasetId"), 0U));
            config.timeout_us = parse_uint32(element->Attribute("timeout"), 0U);
            config.src_ip = parse_ip_address(element->Attribute("srcIp"), 0U);

            if (config.com_id == 0U) {
                std::cerr << "Subscriber element missing comId" << std::endl;
                return false;
            }
            subscriber_config = config;
        }
    }

    std::lock_guard<std::mutex> lock(mutex_);
    configuration_xml_ = xml_content;
    publisher_config_ = publisher_config;
    subscriber_config_ = subscriber_config;

    if (publisher_config_) {
        if (publisher_config_->dataset_size == 0U && !outgoing_payload_.empty()) {
            publisher_config_->dataset_size = static_cast<uint32_t>(outgoing_payload_.size());
        }
        if (publisher_config_->dataset_size == 0U) {
            publisher_config_->dataset_size = static_cast<uint32_t>(outgoing_payload_.size());
        }
    }

    if (!outgoing_payload_.empty()) {
        outgoing_payload_hex_ = bytes_to_hex(outgoing_payload_);
    }
    return true;
}

bool TrdpManager::update_outgoing_payload(const std::string &payload_hex) {
    std::vector<uint8_t> bytes;
    if (!hex_to_bytes(payload_hex, bytes)) {
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (publisher_config_ && publisher_config_->dataset_size != 0U &&
        bytes.size() != publisher_config_->dataset_size) {
        std::cerr << "Payload size does not match dataset size" << std::endl;
        return false;
    }

    outgoing_payload_ = bytes;
    outgoing_payload_hex_ = bytes_to_hex(outgoing_payload_);

    if (running_ && publisher_handle_ != nullptr && !outgoing_payload_.empty()) {
        TRDP_RESULT result = tlp_put(app_handle_,
                                     publisher_handle_,
                                     outgoing_payload_.data(),
                                     static_cast<UINT16>(outgoing_payload_.size()),
                                     TRUE);
        if (result != TRDP_NO_ERR) {
            std::cerr << "Failed to push payload to TRDP stack: " << result << std::endl;
            return false;
        }
    }

    return true;
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

void TrdpManager::pd_receive_callback(void *pRefCon,
                                      TRDP_APP_SESSION_T,
                                      const TRDP_PD_INFO_T *pPdInfo,
                                      const UINT8 *pData,
                                      UINT32 dataSize) {
    auto *manager = static_cast<TrdpManager *>(pRefCon);
    manager->handle_pd_message(pPdInfo, pData, dataSize);
}

void TrdpManager::log_callback(void *,
                               TRDP_LOG_T,
                               const CHAR8 *,
                               const CHAR8 *pFile,
                               UINT16 line,
                               const CHAR8 *pMsg) {
    if (pMsg != nullptr) {
        std::cerr << "[TRDP] " << (pFile ? pFile : "?") << ":" << line << " " << pMsg << std::endl;
    }
}

void TrdpManager::handle_pd_message(const TRDP_PD_INFO_T *pPdInfo,
                                    const UINT8 *pData,
                                    UINT32 dataSize) {
    if (pPdInfo == nullptr || pData == nullptr) {
        return;
    }

    TrdpIncomingMessage message;
    message.source_ip = ip_to_string(pPdInfo->srcIpAddr);

    std::ostringstream com_id_stream;
    com_id_stream << "0x" << std::hex << std::uppercase << pPdInfo->comId;
    message.com_id = com_id_stream.str();

    std::ostringstream dataset_stream;
    dataset_stream << "0x" << std::hex << std::uppercase << pPdInfo->datasetId;
    message.dataset_id = dataset_stream.str();

    std::vector<uint8_t> payload(pData, pData + dataSize);
    message.payload_hex = bytes_to_hex(payload);
    message.timestamp = current_timestamp();

    std::lock_guard<std::mutex> lock(mutex_);
    message_queue_.push_back(std::move(message));
}

bool TrdpManager::open_session_locked() {
    if (session_open_) {
        return true;
    }

    TRDP_RESULT result = tlc_init(&app_handle_,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  nullptr,
                                  &TrdpManager::log_callback,
                                  &TrdpManager::log_callback,
                                  this);
    if (result != TRDP_NO_ERR) {
        std::cerr << "tlc_init failed: " << result << std::endl;
        return false;
    }

    TRDP_IP_ADDR_T own_ip = 0U;
    TRDP_IP_ADDR_T mc_group = 0U;
    UINT16 port = 17224; // default PD port

    result = tlc_openSession(app_handle_,
                              own_ip,
                              0U,
                              port,
                              0U,
                              &TrdpManager::pd_receive_callback,
                              this);
    if (result != TRDP_NO_ERR) {
        std::cerr << "tlc_openSession failed: " << result << std::endl;
        tlc_terminate();
        app_handle_ = nullptr;
        return false;
    }

    session_open_ = true;
    subscriber_handle_ = nullptr;
    publisher_handle_ = nullptr;
    return true;
}

void TrdpManager::close_session_locked() {
    if (!session_open_) {
        return;
    }

    if (publisher_handle_ != nullptr) {
        tlp_unpublish(app_handle_, publisher_handle_);
        publisher_handle_ = nullptr;
    }
    if (subscriber_handle_ != nullptr) {
        tlp_unsubscribe(app_handle_, subscriber_handle_);
        subscriber_handle_ = nullptr;
    }

    tlc_closeSession(app_handle_);
    tlc_terminate();
    app_handle_ = nullptr;
    session_open_ = false;
}

bool TrdpManager::configure_publication_locked() {
    if (!publisher_config_) {
        return true;
    }

    TRDP_SEND_PARAM_T send_param;
    std::memset(&send_param, 0, sizeof(send_param));
    send_param.comId = publisher_config_->com_id;
    send_param.datasetId = publisher_config_->dataset_id;
    send_param.cycle = publisher_config_->cycle_time_us;
    send_param.timeout = publisher_config_->reply_timeout;
    send_param.qos = publisher_config_->qos;

    TRDP_RESULT result = tlp_publish(app_handle_,
                                     &publisher_handle_,
                                     publisher_config_->dest_ip,
                                     0U,
                                     publisher_config_->com_id,
                                     publisher_config_->topo_counter,
                                     0U,
                                     &send_param,
                                     outgoing_payload_.empty() ? nullptr : outgoing_payload_.data(),
                                     static_cast<UINT16>(outgoing_payload_.size()));
    if (result != TRDP_NO_ERR) {
        std::cerr << "tlp_publish failed: " << result << std::endl;
        return false;
    }

    return true;
}

bool TrdpManager::configure_subscription_locked() {
    if (!subscriber_config_) {
        return true;
    }

    TRDP_RESULT result = tlp_subscribe(app_handle_,
                                       &subscriber_handle_,
                                       nullptr,
                                       subscriber_config_->com_id,
                                       subscriber_config_->dataset_id,
                                       0U,
                                       0U,
                                       subscriber_config_->timeout_us,
                                       0U,
                                       subscriber_config_->src_ip,
                                       TRDP_TO_DEFAULT,
                                       FALSE,
                                       &TrdpManager::pd_receive_callback,
                                       this,
                                       TRUE);
    if (result != TRDP_NO_ERR) {
        std::cerr << "tlp_subscribe failed: " << result << std::endl;
        return false;
    }

    return true;
}

void TrdpManager::process_loop() {
    while (!terminate_requested_.load()) {
        TRDP_TIME_T interval;
        interval.tv_sec = 0;
        interval.tv_usec = 50000; // 50 ms

        TRDP_RESULT result = tlc_process(app_handle_, &interval);
        if (result != TRDP_NO_ERR && result != TRDP_TIMEOUT_ERR) {
            std::cerr << "tlc_process returned error: " << result << std::endl;
        }
    }
}
