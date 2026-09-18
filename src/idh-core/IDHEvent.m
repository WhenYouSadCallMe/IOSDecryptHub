#import "IDHEvent.h"

NSInteger const IDHEventSchemaVersion = 1;

static NSString *IDHISO8601Date(NSDate *date) {
    static NSISO8601DateFormatter *formatter;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        formatter = [[NSISO8601DateFormatter alloc] init];
        formatter.formatOptions = NSISO8601DateFormatWithInternetDateTime |
                                  NSISO8601DateFormatWithFractionalSeconds |
                                  NSISO8601DateFormatWithColonSeparatorInTime;
    });
    return [formatter stringFromDate:date];
}

@implementation IDHEvent

- (instancetype)init {
    return [self initWithType:@"system" operation:@"unknown" bundleID:nil];
}

- (instancetype)initWithType:(NSString *)type
                    operation:(NSString *)operation
                    bundleID:(NSString *)bundleID {
    self = [super init];
    if (!self) return nil;
    _eventID = [NSUUID UUID].UUIDString.lowercaseString;
    _timestamp = [NSDate date];
    _layer = @"unknown";
    _type = [type copy] ?: @"unknown";
    _operation = [operation copy] ?: @"unknown";
    _bundleID = [bundleID copy];
    _nativeStack = @[];
    _jsStack = @[];
    _valueRefs = @[];
    _tags = @[];
    _confidence = 0;
    _sensitivity = IDHEventSensitivityMasked;
    return self;
}

- (id)copyWithZone:(NSZone *)zone {
    IDHEvent *copy = [[[self class] allocWithZone:zone] initWithType:self.type
                                                              operation:self.operation
                                                              bundleID:self.bundleID];
    copy.eventID = self.eventID;
    copy.sessionID = self.sessionID;
    copy.timestamp = self.timestamp;
    copy.pid = self.pid;
    copy.tid = self.tid;
    copy.image = self.image;
    copy.aslrSlide = self.aslrSlide;
    copy.flowID = self.flowID;
    copy.requestID = self.requestID;
    copy.parentEventID = self.parentEventID;
    copy.layer = self.layer;
    copy.arguments = self.arguments;
    copy.result = self.result;
    copy.nativeStack = self.nativeStack;
    copy.jsStack = self.jsStack;
    copy.valueRefs = self.valueRefs;
    copy.tags = self.tags;
    copy.confidence = self.confidence;
    copy.evidence = self.evidence;
    copy.analysis = self.analysis;
    copy.sensitivity = self.sensitivity;
    copy.dropped = self.dropped;
    return copy;
}

- (NSDictionary *)dictionaryRepresentation {
    NSMutableDictionary *out = [@{
        @"schemaVersion": @(IDHEventSchemaVersion),
        @"eventId": self.eventID ?: @"",
        @"timestamp": IDHISO8601Date(self.timestamp ?: [NSDate date]),
        @"type": self.type ?: @"",
        @"operation": self.operation ?: @"",
        @"sensitivity": @(self.sensitivity),
    } mutableCopy];
    NSMutableDictionary *target = [NSMutableDictionary dictionary];
    if (self.bundleID.length) target[@"bundleId"] = self.bundleID;
    if (self.pid) target[@"pid"] = @(self.pid);
    if (self.tid) target[@"tid"] = @(self.tid);
    if (self.image.length) target[@"image"] = self.image;
    if (target.count) out[@"target"] = target;
    NSMutableDictionary *optional = [NSMutableDictionary dictionary];
    if (self.sessionID) optional[@"sessionId"] = self.sessionID;
    if (self.aslrSlide) optional[@"aslrSlide"] = self.aslrSlide;
    if (self.flowID) optional[@"flowId"] = self.flowID;
    if (self.requestID) optional[@"requestId"] = self.requestID;
    if (self.parentEventID) optional[@"parentEventId"] = self.parentEventID;
    if (self.layer) optional[@"layer"] = self.layer;
    if (self.arguments) optional[@"arguments"] = self.arguments;
    if (self.result) optional[@"result"] = self.result;
    if (self.nativeStack) optional[@"nativeStack"] = self.nativeStack;
    if (self.jsStack) optional[@"jsStack"] = self.jsStack;
    if (self.valueRefs) optional[@"valueRefs"] = self.valueRefs;
    if (self.tags) optional[@"tags"] = self.tags;
    if (self.evidence) optional[@"evidence"] = self.evidence;
    if (self.analysis) optional[@"analysis"] = self.analysis;
    [optional enumerateKeysAndObjectsUsingBlock:^(NSString *key, id value, BOOL *stop) {
        if (value) out[key] = value;
    }];
    if (self.confidence > 0) out[@"confidence"] = @(self.confidence);
    if (self.dropped) out[@"dropped"] = @YES;
    return out;
}

- (nullable NSData *)JSONData:(NSError **)error {
    if (![self validate:error]) return nil;
    return [NSJSONSerialization dataWithJSONObject:[self dictionaryRepresentation]
                                             options:0
                                               error:error];
}

- (BOOL)validate:(NSError **)error {
    NSString *message = nil;
    if (!self.eventID.length) message = @"eventId is required";
    else if (!self.timestamp) message = @"timestamp is required";
    else if (!self.type.length) message = @"type is required";
    else if (!self.operation.length) message = @"operation is required";
    else if (self.confidence < 0 || self.confidence > 1) message = @"confidence must be between 0 and 1";
    if (message && error) {
        *error = [NSError errorWithDomain:@"IOSDecryptHub.Event"
                                      code:1
                                  userInfo:@{NSLocalizedDescriptionKey: message}];
    }
    return message == nil;
}

@end
