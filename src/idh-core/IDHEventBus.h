#import <Foundation/Foundation.h>
#import "IDHEvent.h"

NS_ASSUME_NONNULL_BEGIN

typedef void (^IDHEventHandler)(IDHEvent *event);

/// Ordered, synchronous event bus for the in-process Agent. A handler should
/// be lightweight and hand off expensive serialization to the host transport.
/// Synchronous delivery provides natural backpressure and preserves ordering.
@interface IDHEventBus : NSObject

- (NSString *)subscribe:(IDHEventHandler)handler;
- (BOOL)unsubscribe:(NSString *)subscriptionID;
- (BOOL)publish:(IDHEvent *)event error:(NSError **)error;
- (NSDictionary *)statistics;
- (void)close;

@end

NS_ASSUME_NONNULL_END
