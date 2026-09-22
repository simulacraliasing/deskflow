/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
 */

#pragma once

#include "server/ClientProxy1_8.h"

#include "net/MouseDatagram.h"

//! Proxy for a protocol 1.9 client with an optional UDP mouse channel.
class ClientProxy1_9 : public ClientProxy1_8
{
public:
  ClientProxy1_9(
      const std::string &name, deskflow::IStream *adoptedStream, Server *server, IEventQueue *events,
      deskflow::datagram::MouseDatagramServer *mouseDatagrams
  );
  ~ClientProxy1_9() override;

  void mouseMove(int32_t xAbs, int32_t yAbs) override;

private:
  deskflow::datagram::MouseDatagramServer *m_mouseDatagrams = nullptr;
  deskflow::datagram::SessionToken m_token;
  uint64_t m_motionSequence = 0;
};
