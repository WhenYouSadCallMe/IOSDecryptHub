#import "IDHNetworkObserver.h"

#import "IDHAnalysisProfiler.h"

static NSDictionary *IDHSafeHeaders(NSDictionary *headers) {
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    [headers enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
        NSString *name = [NSString stringWithFormat:@"%@", key];
        NSString *lower = name.lowercaseString;
        BOOL sensitive = [lower containsString:@"authorization"] || [lower containsString:@"cookie"] || [lower containsString:@"token"] || [lower containsString:@"password"];
        result[name] = sensitive ? @"<redacted>" : [NSString stringWithFormat:@"%@", value];
    }];
    return result;
}

@implementation IDHNetworkObserver

- (BOOL)recordRequestWithURL:(NSString *)url method:(NSString *)method headers:(NSDictionary *)headers body:(NSData *)body requestID:(NSString *)requestID error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"network" operation:@"request" bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"network";
    event.requestID = requestID;
    event.arguments = @{
        @"url": url ?: @"",
        @"method": method ?: @"GET",
        @"headers": IDHSafeHeaders(headers ?: @{}),
        @"body": body ? IDHProfileData(body) : @{},
    };
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

- (BOOL)recordResponseWithURL:(NSString *)url status:(NSInteger)status headers:(NSDictionary *)headers body:(NSData *)body requestID:(NSString *)requestID error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"network" operation:@"response" bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"network";
    event.requestID = requestID;
    event.arguments = @{ @"url": url ?: @"", @"status": @(status), @"headers": IDHSafeHeaders(headers ?: @{}) };
    event.result = body ? IDHProfileData(body) : @{};
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

- (BOOL)recordTLSBytes:(NSData *)bytes direction:(NSString *)direction requestID:(NSString *)requestID error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"network" operation:@"tls.plaintext" bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"tls-observer";
    event.requestID = requestID;
    event.arguments = @{ @"direction": direction ?: @"unknown" };
    event.result = IDHProfileData(bytes ?: [NSData data]);
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

@end
