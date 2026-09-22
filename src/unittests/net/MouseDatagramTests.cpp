/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: MIT
 */

#include "MouseDatagramTests.h"

#include "net/MouseDatagram.h"

#include <QTest>

using namespace deskflow::datagram;

namespace {

SessionToken testToken()
{
  SessionToken token;
  for (size_t i = 0; i < token.bytes.size(); ++i) {
    token.bytes[i] = static_cast<uint8_t>(i);
  }
  return token;
}

} // namespace

void MouseDatagramTests::motionRoundTrip()
{
  const auto token = testToken();
  const Motion sent{.sequence = 0x0102030405060708ULL, .x = -123, .y = 456};
  const auto packet = MouseDatagramProtocol::makeMotion(token, sent);

  PacketType type = PacketType::Registration;
  SessionToken receivedToken;
  Motion received;
  QVERIFY(MouseDatagramProtocol::parse(packet.data(), packet.size(), type, receivedToken, received));
  QCOMPARE(type, PacketType::Motion);
  QCOMPARE(receivedToken.bytes, token.bytes);
  QCOMPARE(received.sequence, sent.sequence);
  QCOMPARE(received.x, sent.x);
  QCOMPARE(received.y, sent.y);
}

void MouseDatagramTests::modifiedPacketIsRejected()
{
  auto packet = MouseDatagramProtocol::makeMotion(testToken(), {.sequence = 1, .x = 10, .y = 20});
  packet[32] ^= 0x01;

  PacketType type = PacketType::Registration;
  SessionToken token;
  Motion motion;
  QVERIFY(!MouseDatagramProtocol::parse(packet.data(), packet.size(), type, token, motion));
}

void MouseDatagramTests::registrationConfirmRoundTrip()
{
  const auto token = testToken();
  const auto packet = MouseDatagramProtocol::makeRegistrationConfirm(token);

  PacketType type = PacketType::Registration;
  SessionToken receivedToken;
  Motion motion;
  QVERIFY(MouseDatagramProtocol::parse(packet.data(), packet.size(), type, receivedToken, motion));
  QCOMPARE(type, PacketType::RegistrationConfirm);
  QCOMPARE(receivedToken.bytes, token.bytes);
  QCOMPARE(motion.sequence, 0ULL);
  QCOMPARE(motion.x, 0);
  QCOMPARE(motion.y, 0);
}

void MouseDatagramTests::sequencesOnlyAdvance()
{
  QVERIFY(MouseDatagramProtocol::isNewerSequence(1, 0));
  QVERIFY(MouseDatagramProtocol::isNewerSequence(42, 41));
  QVERIFY(!MouseDatagramProtocol::isNewerSequence(42, 42));
  QVERIFY(!MouseDatagramProtocol::isNewerSequence(41, 42));
}

QTEST_MAIN(MouseDatagramTests)
