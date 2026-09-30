/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <systemd/sd-varlink-idl.h>

static SD_VARLINK_DEFINE_METHOD(GetStatus,
        SD_VARLINK_DEFINE_OUTPUT(locked, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(desktopLocked, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(manualLocked, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(itemCount, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_OUTPUT(encrypted, SD_VARLINK_BOOL, 0),
        SD_VARLINK_DEFINE_OUTPUT(sessionTracked, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_OUTPUT(homeStorage, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(Item,
        SD_VARLINK_DEFINE_FIELD(label, SD_VARLINK_STRING, 0),
        SD_VARLINK_DEFINE_FIELD(attributes, SD_VARLINK_STRING, SD_VARLINK_MAP),
        SD_VARLINK_DEFINE_FIELD(created, SD_VARLINK_INT, 0),
        SD_VARLINK_DEFINE_FIELD(modified, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(ListItems,
        SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(items, Item, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_INTERFACE(io_platformd_Secret, "io.platformd.Secret",
        &vl_method_GetStatus,
        &vl_type_Item,
        &vl_method_ListItems);
