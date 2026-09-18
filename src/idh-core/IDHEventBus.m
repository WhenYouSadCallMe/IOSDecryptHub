#import "IDHEventBus.h"

@implementation IDHEventBus {
    dispatch_queue_t _queue;
    NSMutableDictionary<NSString *, IDHEventHandler> *_handlers;
    uint64_t _published;
    uint64_t _delivered;
    uint64_t _dropped;
    BOOL _closed;
}

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _queue = dispatch_queue_create("com.iosdecrypthub.event-bus", DISPATCH_QUEUE_SERIAL);
    _handlers = [NSMutableDictionary dictionary];
    return self;
}

- (NSString *)subscribe:(IDHEventHandler)handler {
    if (!handler) return @"";
    NSString *identifier = [NSUUID UUID].UUIDString.lowercaseString;
    dispatch_sync(_queue, ^{
        if (!_closed) _handlers[identifier] = [handler copy];
    });
    return identifier;
}

- (BOOL)unsubscribe:(NSString *)subscriptionID {
    if (!subscriptionID.length) return NO;
    __block BOOL removed = NO;
    dispatch_sync(_queue, ^{
        removed = _handlers[subscriptionID] != nil;
        [_handlers removeObjectForKey:subscriptionID];
    });
    return removed;
}

- (BOOL)publish:(IDHEvent *)event error:(NSError **)error {
    if (!event || ![event validate:error]) {
        dispatch_sync(_queue, ^{ _dropped++; });
        return NO;
    }
    __block BOOL accepted = NO;
    __block NSArray *handlers;
    dispatch_sync(_queue, ^{
        if (_closed) {
            _dropped++;
            return;
        }
        accepted = YES;
        _published++;
        handlers = [_handlers.allValues copy];
    });
    if (!accepted && error) {
        *error = [NSError errorWithDomain:@"IOSDecryptHub.EventBus"
                                      code:2
                                  userInfo:@{NSLocalizedDescriptionKey: @"event bus is closed"}];
    }
    // Execute callbacks outside the registry queue. A callback may safely
    // unsubscribe itself, close the bus, or publish a nested event.
    for (IDHEventHandler handler in handlers) {
        handler(event);
        dispatch_sync(_queue, ^{ _delivered++; });
    }
    return accepted;
}

- (NSDictionary *)statistics {
    __block NSDictionary *stats;
    dispatch_sync(_queue, ^{
        stats = @{
            @"subscribers": @(_handlers.count),
            @"published": @(_published),
            @"delivered": @(_delivered),
            @"dropped": @(_dropped),
        };
    });
    return stats;
}

- (void)close {
    dispatch_sync(_queue, ^{
        _closed = YES;
        [_handlers removeAllObjects];
    });
}

@end
