#import "IDHRecordOnlyObserver.h"

NS_ASSUME_NONNULL_BEGIN

@interface IDHCryptoObserver : IDHRecordOnlyObserver

- (BOOL)recordOperation:(NSString *)operation
			algorithm:(NSString *)algorithm
			arguments:(NSDictionary *)arguments
			result:(nullable NSData *)result
			requestID:(nullable NSString *)requestID
			error:(NSError **)error;
- (BOOL)recordTrustEvaluation:(NSString *)operation
						 host:(nullable NSString *)host
					 result:(NSDictionary *)result
					error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
