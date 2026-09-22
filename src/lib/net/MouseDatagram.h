/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
 */

#pragma once

#include "arch/IArchNetwork.h"
#include "net/ISocket.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>

class IEventQueue;
class EventQueueTimer;
class ISocketMultiplexerJob;
class NetworkAddress;
class SocketMultiplexer;

namespace deskflow::datagram {

struct SessionToken
{
  std::array<uint8_t, 16> bytes{};

  bool operator<(const SessionToken &other) const
  {
    return bytes < other.bytes;
  }
};

enum class PacketType : uint8_t
{
  Registration = 1,
  RegistrationAck = 2,
  RegistrationConfirm = 3,
  Motion = 4,
};

struct Motion
{
  uint64_t sequence = 0;
  int16_t x = 0;
  int16_t y = 0;
};

//! POD event payload transferred from the network thread to the client event queue.
struct MouseDatagramMotionInfo
{
  int32_t x = 0;
  int32_t y = 0;
};

class MouseDatagramProtocol
{
public:
  inline static constexpr size_t kPacketSize = 52;

  static SessionToken newSessionToken();
  static std::array<uint8_t, kPacketSize> makeRegistration(const SessionToken &token);
  static std::array<uint8_t, kPacketSize> makeRegistrationAck(const SessionToken &token);
  static std::array<uint8_t, kPacketSize> makeRegistrationConfirm(const SessionToken &token);
  static std::array<uint8_t, kPacketSize> makeMotion(const SessionToken &token, const Motion &motion);
  static bool isNewerSequence(uint64_t sequence, uint64_t lastAccepted);
  static bool parse(const uint8_t *data, size_t size, PacketType &type, SessionToken &token, Motion &motion);
};

//! UDP listener shared by all protocol 1.9 clients on a server.
class MouseDatagramServer : public ISocket
{
public:
  MouseDatagramServer(SocketMultiplexer *socketMultiplexer, const NetworkAddress &address);
  MouseDatagramServer(const MouseDatagramServer &) = delete;
  MouseDatagramServer(MouseDatagramServer &&) = delete;
  ~MouseDatagramServer() override;

  MouseDatagramServer &operator=(const MouseDatagramServer &) = delete;
  MouseDatagramServer &operator=(MouseDatagramServer &&) = delete;

  SessionToken createSession();
  void removeSession(const SessionToken &token);
  bool sendMotion(const SessionToken &token, const Motion &motion);

  void bind(const NetworkAddress &) override;
  void close() override;
  void *getEventTarget() const override;

private:
  struct Session
  {
    ArchNetAddress endpoint = nullptr;
    double lastConfirmation = 0.0;
    bool confirmed = false;
  };

  ISocketMultiplexerJob *service(ISocketMultiplexerJob *, bool readable, bool writable, bool error);
  bool handleRegistration(const SessionToken &token, ArchNetAddress &source);
  bool handleRegistrationConfirm(const SessionToken &token, ArchNetAddress source);
  bool sendPacket(const std::array<uint8_t, MouseDatagramProtocol::kPacketSize> &packet, ArchNetAddress destination);

private:
  ArchSocket m_socket = nullptr;
  SocketMultiplexer *m_socketMultiplexer = nullptr;
  std::map<SessionToken, Session> m_sessions;
  std::mutex m_mutex;
};

//! UDP receiver for one protocol 1.9 client session.
class MouseDatagramClient : public ISocket
{
public:
  MouseDatagramClient(IEventQueue *events, SocketMultiplexer *socketMultiplexer, void *eventTarget);
  MouseDatagramClient(const MouseDatagramClient &) = delete;
  MouseDatagramClient(MouseDatagramClient &&) = delete;
  ~MouseDatagramClient() override;

  MouseDatagramClient &operator=(const MouseDatagramClient &) = delete;
  MouseDatagramClient &operator=(MouseDatagramClient &&) = delete;

  void start(const NetworkAddress &serverAddress, const SessionToken &token);
  bool isActive() const;

  void bind(const NetworkAddress &) override;
  void close() override;
  void *getEventTarget() const override;

private:
  ISocketMultiplexerJob *service(ISocketMultiplexerJob *, bool readable, bool writable, bool error);
  void sendRegistration();
  void sendRegistrationConfirm();
  void handleRegistrationTimer();
  bool fromServer(ArchNetAddress source) const;

private:
  ArchSocket m_socket = nullptr;
  IEventQueue *m_events = nullptr;
  SocketMultiplexer *m_socketMultiplexer = nullptr;
  void *m_eventTarget = nullptr;
  EventQueueTimer *m_registrationTimer = nullptr;
  NetworkAddress *m_serverAddress = nullptr;
  SessionToken m_token;
  std::atomic<uint64_t> m_lastSequence = 0;
  std::atomic<uint64_t> m_lastServerPacketAt = 0;
};

} // namespace deskflow::datagram
