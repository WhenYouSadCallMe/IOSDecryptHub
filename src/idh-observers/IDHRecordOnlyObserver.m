#import "IDHRecordOnlyObserver.h"

@interface IDHRecordOnlyObserver ()
@property(nonatomic, copy, readwrite) NSString *observerID;
@property(nonatomic, readwrite) IDHObserverMode mode;
@property(nonatomic, strong) IDHEventBus *bus;
@property(nonatomic, readwrite, getter=isRunning) BOOL running;
@end

@implementation IDHRecordOnlyObserver

- (instancetype)initWithObserverID:(NSString *)observerID bus:(IDHEventBus *)bus {
    self = [super init];
    if (!self) return nil;
    _observerID = [observerID copy];
    _bus = bus;
    _mode = IDHObserverModeRecordOnly;
    return self;
}

- (BOOL)startWithOptions:(NSDictionary *)options error:(NSError **)error {
    if (!self.bus) {
        if (error) *error = [NSError errorWithDomain:@"IOSDecryptHub.Observer" code:3 userInfo:@{NSLocalizedDescriptionKey: @"event bus is required"}];
        return NO;
    }
    self.running = YES;
    return YES;
}

- (void)stop {
    self.running = NO;
}

- (BOOL)recordEvent:(IDHEvent *)event error:(NSError **)error {
    if (!self.running) {
        if (error) *error = [NSError errorWithDomain:@"IOSDecryptHub.Observer" code:4 userInfo:@{NSLocalizedDescriptionKey: @"observer is not running"}];
        return NO;
    }
    return [self.bus publish:event error:error];
}

@end

static NSError *IDHBridgeError(NSString *message) {
    return [NSError errorWithDomain:@"IOSDecryptHub.WebKitBridge" code:1 userInfo:@{NSLocalizedDescriptionKey: message}];
}

IDHEvent *IDHEventFromWebKitBridgeMessage(NSDictionary *message, NSString *bundleID, NSError **error) {
    if (![message isKindOfClass:[NSDictionary class]]) {
        if (error) *error = IDHBridgeError(@"bridge message must be an object");
        return nil;
    }
    NSString *type = message[@"type"];
    NSString *operation = message[@"operation"] ?: message[@"name"];
    if (![type isKindOfClass:[NSString class]] || !type.length ||
        ![operation isKindOfClass:[NSString class]] || !operation.length) {
        if (error) *error = IDHBridgeError(@"bridge message requires type and operation");
        return nil;
    }
    IDHEvent *event = [[IDHEvent alloc] initWithType:type operation:operation bundleID:bundleID];
    event.layer = @"webkit-js";
    event.arguments = message[@"arguments"] ?: message[@"args"];
    event.result = message[@"result"];
    event.jsStack = [message[@"jsStack"] isKindOfClass:[NSArray class]] ? message[@"jsStack"] : @[];
    event.flowID = [message[@"flowId"] isKindOfClass:[NSString class]] ? message[@"flowId"] : nil;
    event.requestID = [message[@"requestId"] isKindOfClass:[NSString class]] ? message[@"requestId"] : nil;
    event.sensitivity = IDHEventSensitivityMasked;
    if (![event validate:error]) return nil;
    return event;
}
