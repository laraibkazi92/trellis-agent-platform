# Copyright (C) 2026 Laraib Kazi
# SPDX-License-Identifier: Apache-2.0

import asyncio

from core.auth import get_identity_manager

_default_identity_mgr = get_identity_manager()


async def apply_configuration_form(
    form,
    identity,
    *,
    known_secrets,
    known_variables,
    global_secrets=None,
    global_variables=None,
    identity_mgr=None,
) -> tuple[bool, bool]:
    """Apply submitted form values to an identity's secrets/variables.

    Only keys in ``known_secrets``/``known_variables`` are written; empty secret
    values are skipped (blank means "keep current") while variables accept empty
    values. When ``global_secrets``/``global_variables`` are given, keys already
    defined globally are left untouched so per-identity values never shadow the
    global configuration. Returns ``(secrets_updated, variables_updated)``.
    """
    mgr = identity_mgr or _default_identity_mgr

    current_secrets = await asyncio.to_thread(mgr.get_identity_config, identity, "secrets")
    current_variables = await asyncio.to_thread(mgr.get_identity_config, identity, "variables")

    secrets_updated = False
    variables_updated = False

    for key, value in form.items():
        if key in ("csrf_token",):
            continue

        val_str = str(value).strip()

        if key in known_secrets and (global_secrets is None or key not in global_secrets):
            if val_str:  # only update secret if not empty
                current_secrets[key] = val_str
                secrets_updated = True
        elif key in known_variables and (global_variables is None or key not in global_variables):
            current_variables[key] = val_str
            variables_updated = True

    if secrets_updated:
        await asyncio.to_thread(mgr.save_identity_config, identity, "secrets", current_secrets)
    if variables_updated:
        await asyncio.to_thread(mgr.save_identity_config, identity, "variables", current_variables)

    return secrets_updated, variables_updated
