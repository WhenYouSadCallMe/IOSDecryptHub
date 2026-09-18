#import "IDHHookRegistry.h"

#import "IDHProfileLoader.h"

static NSError *IDHRegistryErrorMessage(NSString *message) {
    return [NSError errorWithDomain:@"IOSDecryptHub.HookRegistry"
                                code:1
                            userInfo:@{NSLocalizedDescriptionKey: message}];
}

@implementation IDHHookRegistry {
    dispatch_queue_t _queue;
    NSMutableDictionary<NSString *, NSDictionary *> *_entries;
    uint64_t _generation;
}

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _queue = dispatch_queue_create("com.iosdecrypthub.hook-registry", DISPATCH_QUEUE_SERIAL);
    _entries = [NSMutableDictionary dictionary];
    return self;
}

- (BOOL)registerHook:(NSDictionary *)hook error:(NSError **)error {
    if (![hook isKindOfClass:[NSDictionary class]]) {
        if (error) *error = IDHRegistryErrorMessage(@"hook must be an object");
        return NO;
    }
    NSDictionary *profile = @{
        @"schemaVersion": @1,
        @"name": @"single-hook",
        @"hooks": @[hook],
    };
    if (![IDHProfileLoader validateProfile:profile error:error]) return NO;
    NSString *hookID = hook[@"id"];
    __block BOOL accepted = NO;
    dispatch_sync(_queue, ^{
        if (_entries[hookID]) return;
        _generation++;
        BOOL enabled = hook[@"enabled"] == nil || [hook[@"enabled"] boolValue];
        _entries[hookID] = @{
            @"spec": [hook copy],
            @"state": enabled ? @"enabled" : @"disabled",
            @"generation": @(_generation),
        };
        accepted = YES;
    });
    if (!accepted && error) *error = IDHRegistryErrorMessage([NSString stringWithFormat:@"hook already registered: %@", hookID]);
    return accepted;
}

- (BOOL)installProfile:(NSDictionary *)profile error:(NSError **)error {
    if (![IDHProfileLoader validateProfile:profile error:error]) return NO;
    NSArray *hooks = profile[@"hooks"];
    __block BOOL accepted = NO;
    dispatch_sync(_queue, ^{
        for (NSDictionary *hook in hooks) {
            NSString *hookID = hook[@"id"];
            if (_entries[hookID]) return;
        }
        for (NSDictionary *hook in hooks) {
            NSString *hookID = hook[@"id"];
            _generation++;
            BOOL enabled = hook[@"enabled"] == nil || [hook[@"enabled"] boolValue];
            _entries[hookID] = @{
                @"spec": [hook copy],
                @"state": enabled ? @"enabled" : @"disabled",
                @"generation": @(_generation),
            };
        }
        accepted = YES;
    });
    if (!accepted && error) *error = IDHRegistryErrorMessage(@"profile contains a hook id that is already registered");
    return accepted;
}

- (BOOL)setEnabled:(BOOL)enabled forHookID:(NSString *)hookID error:(NSError **)error {
    if (!hookID.length) {
        if (error) *error = IDHRegistryErrorMessage(@"hook id is required");
        return NO;
    }
    __block BOOL accepted = NO;
    dispatch_sync(_queue, ^{
        NSDictionary *entry = _entries[hookID];
        if (!entry) return;
        _generation++;
        _entries[hookID] = @{
            @"spec": entry[@"spec"],
            @"state": enabled ? @"enabled" : @"disabled",
            @"generation": @(_generation),
        };
        accepted = YES;
    });
    if (!accepted && error) *error = IDHRegistryErrorMessage([NSString stringWithFormat:@"hook not found: %@", hookID]);
    return accepted;
}

- (BOOL)unregisterHookID:(NSString *)hookID error:(NSError **)error {
    if (!hookID.length) {
        if (error) *error = IDHRegistryErrorMessage(@"hook id is required");
        return NO;
    }
    __block BOOL accepted = NO;
    dispatch_sync(_queue, ^{
        if (!_entries[hookID]) return;
        [_entries removeObjectForKey:hookID];
        _generation++;
        accepted = YES;
    });
    if (!accepted && error) *error = IDHRegistryErrorMessage([NSString stringWithFormat:@"hook not found: %@", hookID]);
    return accepted;
}

- (NSDictionary *)entryForHookID:(NSString *)hookID {
    if (!hookID.length) return nil;
    __block NSDictionary *entry;
    dispatch_sync(_queue, ^{ entry = [_entries[hookID] copy]; });
    return entry;
}

- (NSArray<NSDictionary *> *)snapshot {
    __block NSArray *entries;
    dispatch_sync(_queue, ^{
        entries = [_entries.allValues sortedArrayUsingComparator:^NSComparisonResult(NSDictionary *left, NSDictionary *right) {
            NSString *leftID = left[@"spec"][@"id"] ?: @"";
            NSString *rightID = right[@"spec"][@"id"] ?: @"";
            return [leftID compare:rightID];
        }];
        entries = [[NSArray alloc] initWithArray:entries copyItems:YES];
    });
    return entries ?: @[];
}

@end
