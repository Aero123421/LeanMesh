#include "pty.hpp"

#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>

namespace meshsim {

Pty::~Pty() {
    if (slave_keepalive_ >= 0) {
        ::close(slave_keepalive_);
    }
    if (master_ >= 0) {
        ::close(master_);
    }
}

bool Pty::open() {
    master_ = ::posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (master_ < 0 || ::grantpt(master_) != 0 || ::unlockpt(master_) != 0) {
        return false;
    }
    const char *name = ::ptsname(master_);
    if (name == nullptr) {
        return false;
    }
    path_ = name;
    slave_keepalive_ = ::open(name, O_RDWR | O_NOCTTY);
    if (slave_keepalive_ < 0) {
        return false;
    }
    termios tio{};
    if (::tcgetattr(slave_keepalive_, &tio) != 0) {
        return false;
    }
    ::cfmakeraw(&tio);
    return ::tcsetattr(slave_keepalive_, TCSANOW, &tio) == 0;
}

std::size_t Pty::read(uint8_t *buf, std::size_t cap) {
    const ssize_t n = ::read(master_, buf, cap);
    return n > 0 ? static_cast<std::size_t>(n) : 0;
}

std::size_t Pty::write(const uint8_t *buf, std::size_t len) {
    const ssize_t n = ::write(master_, buf, len);
    return n > 0 ? static_cast<std::size_t>(n) : 0;
}

} // namespace meshsim
