#import "IDHRecordOnlyObserver.h"

NS_ASSUME_NONNULL_BEGIN

@interface IDHWebKitObserver : IDHRecordOnlyObserver

- (BOOL)recordBridgeMessage:(NSDictionary *)message
				bundleID:(NSString *)bundleID
				  error:(NSError **)error;
- (BOOL)recordJavaScriptEvent:(NSString *)operation
					arguments:(nullable id)arguments
					   result:(nullable id)result
					 jsStack:(nullable NSArray<NSDictionary *> *)jsStack
					  flowID:(nullable NSString *)flowID
				 requestID:(nullable NSString *)requestID
					  error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
