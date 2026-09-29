// Pseudo-terminal that stands in for the root's authenticated USB serial port. The Host opens the
// slave path with pyserial exactly as it would open /dev/ttyACM0.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace meshsim {

class Pty {
  public:
    Pty() = default;
    ~Pty();
    Pty(const Pty &) = delete;
    Pty &operator=(const Pty &) = delete;

    // Creates the pty in raw mode. Returns false (with errno set) on failure.
    bool open();
    [[nodiscard]] int master_fd() const { return master_; }
    [[nodiscard]] const std::string &slave_path() const { return path_; }
    // Non-blocking read of what the host wrote; 0 when nothing is pending.
    std::size_t read(uint8_t *buf, std::size_t cap);
    // Best-effort write towards the host (the host may not have the port open).
    std::size_t write(const uint8_t *buf, std::size_t len);

  private:
    int master_ = -1;
    int slave_keepalive_ = -1; // keeps the master readable while the host reconnects
    std::string path_;
};

} // namespace meshsim
