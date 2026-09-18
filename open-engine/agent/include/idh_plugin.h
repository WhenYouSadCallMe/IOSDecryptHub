#ifndef IDH_PLUGIN_H
#define IDH_PLUGIN_H

#include <stddef.h>
#include <stdint.h>

#include "idh_event.h"

#define IDH_PLUGIN_ABI_MAJOR 1u
#define IDH_PLUGIN_ABI_MINOR 0u

typedef struct idh_plugin_api idh_plugin_api_t;
typedef struct idh_hook_registry idh_hook_registry_t;

typedef struct idh_plugin_info {
    uint32_t abi_major;
    uint32_t abi_minor;
    const char *plugin_id;
    const char *plugin_version;
} idh_plugin_info_t;

/* The Agent owns these opaque handles and controls their lifetime. */
struct idh_plugin_api {
    uint32_t abi_major;
    uint32_t abi_minor;
    const idh_plugin_info_t *(*agent_info)(void);
    void (*log)(int level, const char *message);
    int (*emit_json)(const char *json, size_t length);
};

/* A native plugin exports these symbols from a pre-signed binary. */
int idh_plugin_init(const idh_plugin_api_t *api);
int idh_plugin_register_hooks(idh_hook_registry_t *registry);
int idh_plugin_on_event(const idh_event_view_t *event);
void idh_plugin_shutdown(void);

#endif /* IDH_PLUGIN_H */
