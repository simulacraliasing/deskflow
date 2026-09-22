/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
 */

#include "net/MouseDatagram.h"

#include "arch/Arch.h"
#include "arch/ArchException.h"
#include "base/Event.h"
#include "base/IEventQueue.h"
#include "base/Log.h"
#include "net/NetworkAddress.h"
#include "net/SocketMultiplexer.h"
#include "net/TSocketMultiplexerMethodJob.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <stdexcept>
#include <tuple>

namespace deskflow::datagram {

namespace {

constexpr std::array<uint8_t, 4> kMagic = {'D', 'F', 'U', 'D'};
constexpr uint8_t kVersion = 1;
constexpr size_t kHeaderSize = 36;
constexpr size_t kTagSize = MouseDatagramProtocol::kPacketSize - kHeaderSize;
constexpr uint64_t kClientSessionTimeoutMs = 3000;
constexpr double kServerSessionTimeoutSeconds = 3.0;

uint64_t nowMilliseconds()
{
  using namespace std::chrono;
  return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
}

void writeUint16(uint8_t *data, size_t offset, uint16_t value)
{
  data[offset] = static_cast<uint8_t>(value >> 8U);
  data[offset + 1] = static_cast<uint8_t>(value);
}

void writeUint64(uint8_t *data, size_t offset, uint64_t value)
{
  for (size_t i = 0; i < sizeof(value); ++i) {
    data[offset + i] = static_cast<uint8_t>(value >> ((sizeof(value) - i - 1U) * 8U));
  }
}

uint16_t readUint16(const uint8_t *data, size_t offset)
{
  return static_cast<uint16_t>((static_cast<uint16_t>(data[offset]) << 8U) | data[offset + 1]);
}

uint64_t readUint64(const uint8_t *data, size_t offset)
{
  uint64_t value = 0;
  for (size_t i = 0; i < sizeof(value); ++i) {
    value = (value << 8U) | data[offset + i];
  }
  return value;
}

std::array<uint8_t, MouseDatagramProtocol::kPacketSize>
makePacket(const PacketType type, const SessionToken &token, const Motion &motion)
{
  std::array<uint8_t, MouseDatagramProtocol::kPacketSize> packet{};
  std::copy(kMagic.begin(), kMagic.end(), packet.begin());
  packet[4] = kVersion;
  packet[5] = static_cast<uint8_t>(type);
  std::copy(token.bytes.begin(), token.bytes.end(), packet.begin() + 8);
  writeUint64(packet.data(), 24, motion.sequence);
  writeUint16(packet.data(), 32, static_cast<uint16_t>(motion.x));
  writeUint16(packet.data(), 34, static_cast<uint16_t>(motion.y));

  std::array<uint8_t, EVP_MAX_MD_SIZE> fullTag{};
  unsigned int tagLength = 0;
  const auto *tag = HMAC(
      EVP_sha256(), token.bytes.data(), static_cast<int>(token.bytes.size()), packet.data(), kHeaderSize,
      fullTag.data(), &tagLength
  );
  if (tag == nullptr || tagLength < kTagSize) {
    throw std::runtime_error("failed to authenticate mouse datagram");
  }
  std::copy_n(fullTag.begin(), kTagSize, packet.begin() + kHeaderSize);
  return packet;
}

} // namespace

SessionToken MouseDatagramProtocol::newSessionToken()
{
  SessionToken token;
  if (RAND_bytes(token.bytes.data(), static_cast<int>(token.bytes.size())) != 1) {
    throw std::runtime_error("failed to generate mouse datagram session token");
  }
  return token;
}

std::array<uint8_t, MouseDatagramProtocol::kPacketSize>
MouseDatagramProtocol::makeRegistration(const SessionToken &token)
{
  return makePacket(PacketType::Registration, token, {});
}

std::array<uint8_t, MouseDatagramProtocol::kPacketSize>
MouseDatagramProtocol::makeRegistrationAck(const SessionToken &token)
{
  return makePacket(PacketType::RegistrationAck, token, {});
}

std::array<uint8_t, MouseDatagramProtocol::kPacketSize>
MouseDatagramProtocol::makeRegistrationConfirm(const SessionToken &token)
{
  return makePacket(PacketType::RegistrationConfirm, token, {});
}

std::array<uint8_t, MouseDatagramProtocol::kPacketSize>
MouseDatagramProtocol::makeMotion(const SessionToken &token, const Motion &motion)
{
  return makePacket(PacketType::Motion, token, motion);
}

bool MouseDatagramProtocol::isNewerSequence(uint64_t sequence, uint64_t lastAccepted)
{
  return sequence > lastAccepted;
}

bool MouseDatagramProtocol::parse(
    const uint8_t *data, size_t size, PacketType &type, SessionToken &token, Motion &motion
)
{
  if (data == nullptr || size != kPacketSize || !std::equal(kMagic.begin(), kMagic.end(), data) ||
      data[4] != kVersion) {
    return false;
  }

  const auto rawType = data[5];
  if (rawType < static_cast<uint8_t>(PacketType::Registration) || rawType > static_cast<uint8_t>(PacketType::Motion)) {
    return false;
  }

  std::copy_n(data + 8, token.bytes.size(), token.bytes.begin());
  std::array<uint8_t, EVP_MAX_MD_SIZE> expectedTag{};
  unsigned int tagLength = 0;
  const auto *tag = HMAC(
      EVP_sha256(), token.bytes.data(), static_cast<int>(token.bytes.size()), data, kHeaderSize, expectedTag.data(),
      &tagLength
  );
  if (tag == nullptr || tagLength < kTagSize || CRYPTO_memcmp(data + kHeaderSize, expectedTag.data(), kTagSize) != 0) {
    return false;
  }

  type = static_cast<PacketType>(rawType);
  motion.sequence = readUint64(data, 24);
  motion.x = static_cast<int16_t>(readUint16(data, 32));
  motion.y = static_cast<int16_t>(readUint16(data, 34));
  return true;
}

MouseDatagramServer::MouseDatagramServer(SocketMultiplexer *socketMultiplexer, const NetworkAddress &address)
    : m_socketMultiplexer(socketMultiplexer)
{
  if (m_socketMultiplexer == nullptr || !address.isValid()) {
    throw std::invalid_argument("mouse datagram listener requires a socket multiplexer and resolved address");
  }

  m_socket = ARCH->newSocket(ARCH->getAddrFamily(address.getAddress()), IArchNetwork::SocketType::DataGram);
  try {
    ARCH->bindSocket(m_socket, address.getAddress());
  } catch (...) {
    ARCH->closeSocket(m_socket);
    m_socket = nullptr;
    throw;
  }
  m_socketMultiplexer->addSocket(
      this,
      new TSocketMultiplexerMethodJob<MouseDatagramServer>(this, &MouseDatagramServer::service, m_socket, true, false)
  );
  LOG_INFO("listening for authenticated mouse datagrams on UDP %d", address.getPort());
}

MouseDatagramServer::~MouseDatagramServer()
{
  close();
}

SessionToken MouseDatagramServer::createSession()
{
  std::scoped_lock lock(m_mutex);
  SessionToken token;
  do {
    token = MouseDatagramProtocol::newSessionToken();
  } while (m_sessions.contains(token));
  m_sessions.emplace(token, Session{});
  return token;
}

void MouseDatagramServer::removeSession(const SessionToken &token)
{
  std::scoped_lock lock(m_mutex);
  const auto it = m_sessions.find(token);
  if (it == m_sessions.end()) {
    return;
  }
  if (it->second.endpoint != nullptr) {
    ARCH->closeAddr(it->second.endpoint);
  }
  m_sessions.erase(it);
}

bool MouseDatagramServer::sendMotion(const SessionToken &token, const Motion &motion)
{
  ArchNetAddress endpoint = nullptr;
  {
    std::scoped_lock lock(m_mutex);
    const auto it = m_sessions.find(token);
    if (it == m_sessions.end() || it->second.endpoint == nullptr || !it->second.confirmed ||
        (Arch::time() - it->second.lastConfirmation) > kServerSessionTimeoutSeconds) {
      return false;
    }
    endpoint = ARCH->copyAddr(it->second.endpoint);
  }

  try {
    const auto sent = sendPacket(MouseDatagramProtocol::makeMotion(token, motion), endpoint);
    ARCH->closeAddr(endpoint);
    return sent;
  } catch (...) {
    ARCH->closeAddr(endpoint);
    throw;
  }
}

void MouseDatagramServer::bind(const NetworkAddress &)
{
  throw std::logic_error("mouse datagram listener binds during construction");
}

void MouseDatagramServer::close()
{
  // Stop callbacks before taking the session lock: the receive callback also
  // updates sessions and runs on the multiplexer thread.
  if (m_socket != nullptr) {
    m_socketMultiplexer->removeSocket(this);
  }

  std::scoped_lock lock(m_mutex);
  if (m_socket != nullptr) {
    ARCH->closeSocket(m_socket);
    m_socket = nullptr;
  }
  for (auto &[token, session] : m_sessions) {
    if (session.endpoint != nullptr) {
      ARCH->closeAddr(session.endpoint);
    }
  }
  m_sessions.clear();
}

void *MouseDatagramServer::getEventTarget() const
{
  return const_cast<MouseDatagramServer *>(this);
}

ISocketMultiplexerJob *MouseDatagramServer::service(ISocketMultiplexerJob *job, bool readable, bool, bool error)
{
  if (error || !readable) {
    return job;
  }

  while (true) {
    std::array<uint8_t, MouseDatagramProtocol::kPacketSize> packet{};
    ArchNetAddress source = nullptr;
    size_t size = 0;
    try {
      size = ARCH->readDatagram(m_socket, packet.data(), packet.size(), &source);
    } catch (const ArchNetworkException &e) {
      LOG_WARN("error reading mouse datagram: %s", e.what());
      return job;
    }
    if (size == 0) {
      if (source != nullptr) {
        ARCH->closeAddr(source);
      }
      return job;
    }

    PacketType type;
    SessionToken token;
    Motion motion;
    if (MouseDatagramProtocol::parse(packet.data(), size, type, token, motion)) {
      const auto isEmptyControlPacket = motion.sequence == 0 && motion.x == 0 && motion.y == 0;
      if (isEmptyControlPacket) {
        if (type == PacketType::Registration) {
          handleRegistration(token, source);
        } else if (type == PacketType::RegistrationConfirm) {
          handleRegistrationConfirm(token, source);
        }
      }
    }
    if (source != nullptr) {
      ARCH->closeAddr(source);
    }
  }
}

bool MouseDatagramServer::handleRegistration(const SessionToken &token, ArchNetAddress &source)
{
  bool knownSession = false;
  ArchNetAddress ackEndpoint = nullptr;
  {
    std::scoped_lock lock(m_mutex);
    const auto it = m_sessions.find(token);
    if (it != m_sessions.end()) {
      if (it->second.endpoint != nullptr && !ARCH->isEqualAddr(it->second.endpoint, source)) {
        ARCH->closeAddr(it->second.endpoint);
        it->second.endpoint = nullptr;
        it->second.lastConfirmation = 0.0;
        it->second.confirmed = false;
      }
      if (it->second.endpoint == nullptr) {
        it->second.endpoint = source;
        source = nullptr;
      }
      ackEndpoint = ARCH->copyAddr(it->second.endpoint);
      knownSession = true;
    }
  }

  if (knownSession) {
    LOG_DEBUG("registered mouse datagram session from %s", ARCH->addrToString(ackEndpoint).c_str());
    std::ignore = sendPacket(MouseDatagramProtocol::makeRegistrationAck(token), ackEndpoint);
    ARCH->closeAddr(ackEndpoint);
  }
  return knownSession;
}

bool MouseDatagramServer::handleRegistrationConfirm(const SessionToken &token, ArchNetAddress source)
{
  std::scoped_lock lock(m_mutex);
  const auto it = m_sessions.find(token);
  if (it == m_sessions.end() || it->second.endpoint == nullptr || !ARCH->isEqualAddr(it->second.endpoint, source)) {
    return false;
  }

  it->second.lastConfirmation = Arch::time();
  it->second.confirmed = true;
  return true;
}

bool MouseDatagramServer::sendPacket(
    const std::array<uint8_t, MouseDatagramProtocol::kPacketSize> &packet, ArchNetAddress destination
)
{
  try {
    return ARCH->writeDatagram(m_socket, packet.data(), packet.size(), destination) == packet.size();
  } catch (const ArchNetworkException &e) {
    LOG_WARN("error writing mouse datagram: %s", e.what());
    return false;
  }
}

MouseDatagramClient::MouseDatagramClient(IEventQueue *events, SocketMultiplexer *socketMultiplexer, void *eventTarget)
    : m_events(events),
      m_socketMultiplexer(socketMultiplexer),
      m_eventTarget(eventTarget)
{
  if (m_events == nullptr || m_socketMultiplexer == nullptr || m_eventTarget == nullptr) {
    throw std::invalid_argument("mouse datagram client requires events, a socket multiplexer, and event target");
  }
}

MouseDatagramClient::~MouseDatagramClient()
{
  close();
}

void MouseDatagramClient::start(const NetworkAddress &serverAddress, const SessionToken &token)
{
  if (!serverAddress.isValid()) {
    throw std::invalid_argument("mouse datagram server address is not resolved");
  }

  m_serverAddress = new NetworkAddress(serverAddress);
  m_token = token;
  m_lastSequence = 0;
  m_lastServerPacketAt = 0;
  const auto family = ARCH->getAddrFamily(serverAddress.getAddress());
  m_socket = ARCH->newSocket(family, IArchNetwork::SocketType::DataGram);
  ArchNetAddress localAddress = ARCH->newAnyAddr(family);
  try {
    ARCH->bindSocket(m_socket, localAddress);
  } catch (...) {
    ARCH->closeAddr(localAddress);
    throw;
  }
  ARCH->closeAddr(localAddress);

  m_socketMultiplexer->addSocket(
      this,
      new TSocketMultiplexerMethodJob<MouseDatagramClient>(this, &MouseDatagramClient::service, m_socket, true, false)
  );
  m_events->addHandler(EventTypes::Timer, this, [this](const auto &) { handleRegistrationTimer(); });
  m_registrationTimer = m_events->newTimer(1.0, this);
  sendRegistration();
}

bool MouseDatagramClient::isActive() const
{
  const auto lastPacketAt = m_lastServerPacketAt.load();
  return lastPacketAt != 0 && (nowMilliseconds() - lastPacketAt) <= kClientSessionTimeoutMs;
}

void MouseDatagramClient::bind(const NetworkAddress &)
{
  throw std::logic_error("mouse datagram client binds an ephemeral port internally");
}

void MouseDatagramClient::close()
{
  if (m_registrationTimer != nullptr) {
    m_events->removeHandler(EventTypes::Timer, this);
    m_events->deleteTimer(m_registrationTimer);
    m_registrationTimer = nullptr;
  }
  if (m_socket != nullptr) {
    m_socketMultiplexer->removeSocket(this);
    ARCH->closeSocket(m_socket);
    m_socket = nullptr;
  }
  delete m_serverAddress;
  m_serverAddress = nullptr;
  m_lastServerPacketAt = 0;
}

void *MouseDatagramClient::getEventTarget() const
{
  return const_cast<MouseDatagramClient *>(this);
}

ISocketMultiplexerJob *MouseDatagramClient::service(ISocketMultiplexerJob *job, bool readable, bool, bool error)
{
  if (error || !readable) {
    return job;
  }

  while (true) {
    std::array<uint8_t, MouseDatagramProtocol::kPacketSize> packet{};
    ArchNetAddress source = nullptr;
    size_t size = 0;
    try {
      size = ARCH->readDatagram(m_socket, packet.data(), packet.size(), &source);
    } catch (const ArchNetworkException &e) {
      LOG_WARN("error reading mouse datagram: %s", e.what());
      return job;
    }
    if (size == 0) {
      if (source != nullptr) {
        ARCH->closeAddr(source);
      }
      return job;
    }

    PacketType type;
    SessionToken token;
    Motion motion;
    const auto valid = fromServer(source) && MouseDatagramProtocol::parse(packet.data(), size, type, token, motion) &&
                       token.bytes == m_token.bytes;
    ARCH->closeAddr(source);
    if (!valid) {
      continue;
    }

    if (type == PacketType::RegistrationAck) {
      sendRegistrationConfirm();
      continue;
    }
    if (type != PacketType::Motion) {
      continue;
    }

    m_lastServerPacketAt = nowMilliseconds();

    auto lastSequence = m_lastSequence.load();
    while (MouseDatagramProtocol::isNewerSequence(motion.sequence, lastSequence) &&
           !m_lastSequence.compare_exchange_weak(lastSequence, motion.sequence)) {
    }
    if (!MouseDatagramProtocol::isNewerSequence(motion.sequence, lastSequence)) {
      continue;
    }
    auto *eventMotion = static_cast<MouseDatagramMotionInfo *>(malloc(sizeof(MouseDatagramMotionInfo)));
    eventMotion->x = motion.x;
    eventMotion->y = motion.y;
    m_events->addEvent(Event(EventTypes::ClientDatagramMouseMove, m_eventTarget, eventMotion));
  }
}

void MouseDatagramClient::sendRegistration()
{
  if (m_socket == nullptr || m_serverAddress == nullptr) {
    return;
  }
  try {
    const auto packet = MouseDatagramProtocol::makeRegistration(m_token);
    std::ignore = ARCH->writeDatagram(m_socket, packet.data(), packet.size(), m_serverAddress->getAddress());
  } catch (const ArchNetworkException &e) {
    LOG_WARN("error registering mouse datagram session: %s", e.what());
  }
}

void MouseDatagramClient::sendRegistrationConfirm()
{
  if (m_socket == nullptr || m_serverAddress == nullptr) {
    return;
  }
  try {
    const auto packet = MouseDatagramProtocol::makeRegistrationConfirm(m_token);
    std::ignore = ARCH->writeDatagram(m_socket, packet.data(), packet.size(), m_serverAddress->getAddress());
  } catch (const ArchNetworkException &e) {
    LOG_WARN("error confirming mouse datagram registration: %s", e.what());
  }
}

void MouseDatagramClient::handleRegistrationTimer()
{
  sendRegistration();
}

bool MouseDatagramClient::fromServer(ArchNetAddress source) const
{
  return source != nullptr && m_serverAddress != nullptr && ARCH->isEqualAddr(source, m_serverAddress->getAddress());
}

} // namespace deskflow::datagram
