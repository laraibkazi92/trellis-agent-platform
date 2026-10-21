# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

"""Throwaway: exists only to make CI red so the publish gate can be tested."""


def test_gate_selftest_deliberate_failure():
    assert False, "intentional: proving publish-images.yml refuses a red commit"
