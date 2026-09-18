#import "IDHObserver.h"

#import "IDHEventBus.h"
#import "IDHTransport.h"

NS_ASSUME_NONNULL_BEGIN

/// Adapter boundary for already-authorized event producers. It records events
/// supplied by the caller; it never discovers or intercepts a target itself.
@interface IDHRecordOnlyObserver : NSObject <IDHObserver>

- (instancetype)initWithObserverID:(NSString *)observerID bus:(IDHEventBus *)bus;
- (BOOL)recordEvent:(IDHEvent *)event error:(NSError **)error;

@end

/// Converts a structured message from an existing JS bridge/logger into the
/// shared Event Schema. It does not inject JavaScript or access a WebKit
/// process.
FOUNDATION_EXPORT IDHEvent * _Nullable IDHEventFromWebKitBridgeMessage(NSDictionary *message,
                                                                       NSString *bundleID,
                                                                       NSError **error);

NS_ASSUME_NONNULL_END
