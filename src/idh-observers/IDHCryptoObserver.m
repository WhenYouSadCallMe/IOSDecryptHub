#import "IDHCryptoObserver.h"

#import "IDHAnalysisProfiler.h"

@implementation IDHCryptoObserver

- (BOOL)recordOperation:(NSString *)operation algorithm:(NSString *)algorithm arguments:(NSDictionary *)arguments result:(NSData *)result requestID:(NSString *)requestID error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"crypto" operation:operation bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"native-crypto";
    event.requestID = requestID;
    NSMutableDictionary *safeArguments = [NSMutableDictionary dictionaryWithDictionary:arguments ?: @{}];
    if (algorithm.length) safeArguments[@"algorithm"] = algorithm;
    event.arguments = safeArguments;
    if (result) event.result = IDHProfileData(result);
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

- (BOOL)recordTrustEvaluation:(NSString *)operation host:(NSString *)host result:(NSDictionary *)result error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"crypto" operation:operation bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"security-framework";
    event.arguments = host.length ? @{ @"host": host } : @{};
    event.result = result ?: @{};
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

@end
