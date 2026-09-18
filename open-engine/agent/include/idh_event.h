#ifndef IDH_EVENT_H
#define IDH_EVENT_H

/*
 * Stable wire contract for the native Agent. The first implementation sends
 * UTF-8 JSON to the desktop collector; the C ABI intentionally passes opaque
 * bytes so the native layer does not depend on a Go runtime.
 */

#include <stddef.h>
#include <stdint.h>

#define IDH_EVENT_SCHEMA_VERSION 1u

typedef struct idh_event_view {
    uint32_t schema_version;
    const char *json;
    size_t json_length;
} idh_event_view_t;

typedef void (*idh_event_sink_fn)(const idh_event_view_t *event, void *context);

#endif /* IDH_EVENT_H */
