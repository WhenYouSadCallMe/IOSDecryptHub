#import "IDHRecordOnlyObserver.h"

NS_ASSUME_NONNULL_BEGIN

@interface IDHSystemObserver : IDHRecordOnlyObserver

- (BOOL)recordEnvironmentQuery:(NSString *)name
				 category:(NSString *)category
				 valueSummary:(nullable NSDictionary *)valueSummary
					error:(NSError **)error;
- (BOOL)recordImageLoad:(NSString *)imagePath
					 slide:(intptr_t)slide
						error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
