#ifndef IDH_HOOK_H
#define IDH_HOOK_H

#include <stddef.h>
#include <stdint.h>

typedef enum idh_hook_kind {
    IDH_HOOK_C_IMPORT = 1,
    IDH_HOOK_OBJC = 2,
    IDH_HOOK_SWIFT_SYMBOL = 3,
    IDH_HOOK_JAVASCRIPT = 4,
    IDH_HOOK_NOTIFICATION = 5
} idh_hook_kind_t;

typedef struct idh_hook_spec {
    const char *id;
    idh_hook_kind_t kind;
    const char *image;
    const char *class_name;
    const char *selector;
    const char *symbol;
    const char *script;
    double sample_rate;
} idh_hook_spec_t;

typedef struct idh_hook_registry idh_hook_registry_t;

int idh_hook_register(idh_hook_registry_t *registry, const idh_hook_spec_t *spec);
int idh_hook_set_enabled(idh_hook_registry_t *registry, const char *id, int enabled);
int idh_hook_unregister(idh_hook_registry_t *registry, const char *id);
size_t idh_hook_snapshot(const idh_hook_registry_t *registry, char *out, size_t out_size);

#endif /* IDH_HOOK_H */
