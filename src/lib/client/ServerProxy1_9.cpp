/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
 */

#include "client/ServerProxy1_9.h"

#include "base/Log.h"
#include "client/Client.h"
#include "deskflow/ProtocolTypes.h"
#include "deskflow/ProtocolUtil.h"
#include "net/MouseDatagram.h"

#include <cstring>
#include <string>

ServerProxy1_9::ServerProxy1_9(Client *client, deskflow::IStream *stream, IEventQueue *events)
    : ServerProxy1_8(client, stream, events)
{
}

ServerProxy::ConnectionResult ServerProxy1_9::parseHandshakeMessage(const uint8_t *code)
{
  if (memcmp(code, kMsgDMouseDatagram, 4) == 0) {
    enableMouseDatagrams();
    return ConnectionResult::Okay;
  }
  return ServerProxy1_8::parseHandshakeMessage(code);
}

bool ServerProxy1_9::shouldForwardTcpMouse() const
{
  return !getClient()->isMouseDatagramActive();
}

void ServerProxy1_9::enableMouseDatagrams()
{
  std::string tokenBytes;
  ProtocolUtil::readf(getStream(), kMsgDMouseDatagram + 4, &tokenBytes);
  if (tokenBytes.size() != deskflow::datagram::SessionToken{}.bytes.size()) {
    LOG_WARN("server offered an invalid mouse datagram session");
    return;
  }

  deskflow::datagram::SessionToken token;
  std::memcpy(token.bytes.data(), tokenBytes.data(), token.bytes.size());
  getClient()->enableMouseDatagram(token);
}
