/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <systemd/sd-json.h>

int policy_reply_parse(sd_json_variant *parameters, const char *policy, const char *session,
                       bool *ret_satisfied, bool *ret_repairable);
