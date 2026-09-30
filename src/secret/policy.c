/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "policy.h"

#include <errno.h>
#include <string.h>

static bool object_unique(sd_json_variant *object) {
        if (!sd_json_variant_is_object(object) || sd_json_variant_elements(object) > 64)
                return false;
        for (size_t i = 0; i < sd_json_variant_elements(object); i += 2)
                for (size_t j = 0; j < i; j += 2)
                        if (strcmp(sd_json_variant_string(sd_json_variant_by_index(object, i)),
                                   sd_json_variant_string(sd_json_variant_by_index(object, j))) == 0)
                                return false;
        return true;
}

static bool text_valid(const char *text, size_t max) {
        if (!text || strnlen(text, max + 1) > max)
                return false;
        for (const unsigned char *p = (const unsigned char *) text; *p; p++)
                if (*p < 0x20 || *p == 0x7f)
                        return false;
        return true;
}

int policy_reply_parse(sd_json_variant *parameters, const char *policy, const char *session,
                       bool *ret_satisfied, bool *ret_repairable) {
        sd_json_variant *result, *id, *subject, *value, *code, *reason, *window;
        const char *outcome, *reason_code, *positive;

        *ret_satisfied = *ret_repairable = false;
        if (!policy || !session || !object_unique(parameters))
                return -EBADMSG;
        result = sd_json_variant_by_key(parameters, "result");
        if (!object_unique(result))
                return -EBADMSG;
        id = sd_json_variant_by_key(result, "policyId");
        subject = sd_json_variant_by_key(result, "sessionId");
        value = sd_json_variant_by_key(result, "result");
        code = sd_json_variant_by_key(result, "reasonCode");
        reason = sd_json_variant_by_key(result, "reason");
        window = sd_json_variant_by_key(result, "windowSec");
        if (!sd_json_variant_is_string(id) || !sd_json_variant_is_string(subject) ||
            !sd_json_variant_is_string(value) || !sd_json_variant_is_string(code) ||
            !sd_json_variant_is_string(reason) || !sd_json_variant_is_unsigned(window) ||
            strcmp(sd_json_variant_string(id), policy) != 0 ||
            strcmp(sd_json_variant_string(subject), session) != 0)
                return -EBADMSG;
        outcome = sd_json_variant_string(value);
        reason_code = sd_json_variant_string(code);
        if (!text_valid(reason_code, 64) || !text_valid(sd_json_variant_string(reason), 512))
                return -EBADMSG;
        positive = strcmp(policy, "fresh-user-verification") == 0 ? "verification-fresh" :
                   strcmp(policy, "local-trusted-session") == 0 ? "local-trusted-session" : NULL;
        if (!positive)
                return -EBADMSG;
        if (strcmp(outcome, "policy-satisfied") == 0) {
                if (strcmp(reason_code, positive) != 0 || sd_json_variant_unsigned(window) == 0)
                        return -EBADMSG;
                *ret_satisfied = true;
        } else if (strcmp(outcome, "denied") == 0)
                *ret_repairable = strcmp(reason_code, "verification-missing") == 0 ||
                                  strcmp(reason_code, "verification-stale") == 0;
        else
                return -EBADMSG;
        return 0;
}
