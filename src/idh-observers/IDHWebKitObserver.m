#import "IDHWebKitObserver.h"

@implementation IDHWebKitObserver

- (BOOL)recordBridgeMessage:(NSDictionary *)message bundleID:(NSString *)bundleID error:(NSError **)error {
    IDHEvent *event = IDHEventFromWebKitBridgeMessage(message, bundleID, error);
    return event ? [self recordEvent:event error:error] : NO;
}

- (BOOL)recordJavaScriptEvent:(NSString *)operation arguments:(id)arguments result:(id)result jsStack:(NSArray<NSDictionary *> *)jsStack flowID:(NSString *)flowID requestID:(NSString *)requestID error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"js" operation:operation bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"webkit-js";
    event.arguments = arguments;
    event.result = result;
    event.jsStack = jsStack ?: @[];
    event.flowID = flowID;
    event.requestID = requestID;
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

@end
