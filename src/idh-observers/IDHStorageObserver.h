#import "IDHRecordOnlyObserver.h"

NS_ASSUME_NONNULL_BEGIN

@interface IDHStorageObserver : IDHRecordOnlyObserver

- (BOOL)recordKeychainOperation:(NSString *)operation
				 service:(nullable NSString *)service
				 account:(nullable NSString *)account
				 result:(nullable NSDictionary *)result
				error:(NSError **)error;
- (BOOL)recordFileOperation:(NSString *)operation
					 path:(NSString *)path
					result:(nullable NSData *)result
					error:(NSError **)error;
- (BOOL)recordSQLiteOperation:(NSString *)operation
					 database:(NSString *)database
						 sql:(nullable NSString *)sql
					 result:(nullable NSDictionary *)result
					error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
