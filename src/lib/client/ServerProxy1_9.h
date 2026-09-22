/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: GPL-2.0-only WITH LicenseRef-OpenSSL-Exception
 */

#pragma once

#include "client/ServerProxy1_8.h"

//! Proxy for a server implementing protocol version 1.9.
class ServerProxy1_9 : public ServerProxy1_8
{
public:
  ServerProxy1_9(Client *client, deskflow::IStream *stream, IEventQueue *events);
  ~ServerProxy1_9() override = default;

protected:
  ConnectionResult parseHandshakeMessage(const uint8_t *code) override;
  bool shouldForwardTcpMouse() const override;

private:
  void enableMouseDatagrams();
};
