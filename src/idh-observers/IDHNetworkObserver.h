#import "IDHRecordOnlyObserver.h"

NS_ASSUME_NONNULL_BEGIN

@interface IDHNetworkObserver : IDHRecordOnlyObserver

- (BOOL)recordRequestWithURL:(NSString *)url
				method:(NSString *)method
				headers:(nullable NSDictionary *)headers
				 body:(nullable NSData *)body
			 requestID:(nullable NSString *)requestID
				error:(NSError **)error;
- (BOOL)recordResponseWithURL:(nullable NSString *)url
			 status:(NSInteger)status
			 headers:(nullable NSDictionary *)headers
			 body:(nullable NSData *)body
			 requestID:(nullable NSString *)requestID
				error:(NSError **)error;
- (BOOL)recordTLSBytes:(NSData *)bytes
			 direction:(NSString *)direction
			 requestID:(nullable NSString *)requestID
				error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
