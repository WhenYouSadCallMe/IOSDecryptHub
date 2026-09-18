#import <Foundation/Foundation.h>

#import "IDHEvent.h"

NS_ASSUME_NONNULL_BEGIN

/// SQLite-backed event store for the host side. It stores the serialized,
/// already-redacted event and exposes bounded Flow/Request queries.
@interface IDHSQLiteStore : NSObject

- (nullable instancetype)initWithURL:(NSURL *)url error:(NSError **)error;
- (BOOL)appendEvent:(IDHEvent *)event error:(NSError **)error;
- (NSArray<NSDictionary *> *)queryWithFlowID:(nullable NSString *)flowID
                                   requestID:(nullable NSString *)requestID
                                        type:(nullable NSString *)type
                                       limit:(NSUInteger)limit
                                       error:(NSError **)error;
- (void)close;

@end

NS_ASSUME_NONNULL_END
