#import "IDHObserver.h"

@implementation IDHObserverCoordinator {
    NSMutableDictionary<NSString *, id<IDHObserver>> *_observers;
    dispatch_queue_t _queue;
}

- (instancetype)init {
    self = [super init];
    if (!self) return nil;
    _observers = [NSMutableDictionary dictionary];
    _queue = dispatch_queue_create("com.iosdecrypthub.observers", DISPATCH_QUEUE_SERIAL);
    return self;
}

- (void)registerObserver:(id<IDHObserver>)observer {
    if (!observer.observerID.length) return;
    dispatch_sync(_queue, ^{ _observers[observer.observerID] = observer; });
}

- (BOOL)startObserver:(NSString *)observerID options:(NSDictionary *)options error:(NSError **)error {
    __block id<IDHObserver> observer;
    dispatch_sync(_queue, ^{ observer = _observers[observerID]; });
    if (!observer) {
        if (error) *error = [NSError errorWithDomain:@"IOSDecryptHub.Observer" code:1 userInfo:@{NSLocalizedDescriptionKey: @"observer not found"}];
        return NO;
    }
    if (observer.mode != IDHObserverModeRecordOnly) {
        if (error) *error = [NSError errorWithDomain:@"IOSDecryptHub.Observer" code:2 userInfo:@{NSLocalizedDescriptionKey: @"extended/lab observers require an explicit signed adapter"}];
        return NO;
    }
    return [observer startWithOptions:options ?: @{} error:error];
}

- (void)stopObserver:(NSString *)observerID {
    __block id<IDHObserver> observer;
    dispatch_sync(_queue, ^{ observer = _observers[observerID]; });
    [observer stop];
}

- (NSArray<NSString *> *)observerIDs {
    __block NSArray *result;
    dispatch_sync(_queue, ^{ result = [_observers.allKeys sortedArrayUsingSelector:@selector(compare:)]; });
    return result ?: @[];
}

@end
