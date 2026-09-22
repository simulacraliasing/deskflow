/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
 */

#include "server/ClientProxy1_9.h"

#include "base/Log.h"
#include "deskflow/ProtocolTypes.h"
#include "deskflow/ProtocolUtil.h"

#include <string>

ClientProxy1_9::ClientProxy1_9(
    const std::string &name, deskflow::IStream *stream, Server *server, IEventQueue *events,
    deskflow::datagram::MouseDatagramServer *mouseDatagrams
)
    : ClientProxy1_8(name, stream, server, events),
      m_mouseDatagrams(mouseDatagrams)
{
  if (m_mouseDatagrams != nullptr) {
    m_token = m_mouseDatagrams->createSession();
    const std::string tokenBytes(reinterpret_cast<const char *>(m_token.bytes.data()), m_token.bytes.size());
    try {
      ProtocolUtil::writef(getStream(), kMsgDMouseDatagram, &tokenBytes);
    } catch (...) {
      m_mouseDatagrams->removeSession(m_token);
      throw;
    }
  }
}

ClientProxy1_9::~ClientProxy1_9()
{
  if (m_mouseDatagrams != nullptr) {
    m_mouseDatagrams->removeSession(m_token);
  }
}

void ClientProxy1_9::mouseMove(int32_t xAbs, int32_t yAbs)
{
  if (m_mouseDatagrams != nullptr &&
      m_mouseDatagrams->sendMotion(
          m_token, {.sequence = ++m_motionSequence, .x = static_cast<int16_t>(xAbs), .y = static_cast<int16_t>(yAbs)}
      )) {
    return;
  }
  ClientProxy1_8::mouseMove(xAbs, yAbs);
}
