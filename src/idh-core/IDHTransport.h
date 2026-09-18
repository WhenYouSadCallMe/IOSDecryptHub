#import <Foundation/Foundation.h>
#import "IDHEvent.h"

NS_ASSUME_NONNULL_BEGIN

@interface IDHJSONLTransport : NSObject

- (nullable instancetype)initWithURL:(NSURL *)url error:(NSError **)error;
- (BOOL)appendEvent:(IDHEvent *)event error:(NSError **)error;
- (BOOL)flush:(NSError **)error;
- (void)close;
- (NSDictionary *)statistics;

@end

NS_ASSUME_NONNULL_END
