/*
 * Deskflow -- mouse and keyboard sharing utility
 * SPDX-FileCopyrightText: (C) 2026 Deskflow Developers
 * SPDX-License-Identifier: MIT
 */

#pragma once

#include <QObject>

class MouseDatagramTests : public QObject
{
  Q_OBJECT

private Q_SLOTS:
  void motionRoundTrip();
  void modifiedPacketIsRejected();
  void registrationConfirmRoundTrip();
  void sequencesOnlyAdvance();
};
