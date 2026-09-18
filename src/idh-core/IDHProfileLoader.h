#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// JSON profile loader. YAML is intentionally not silently accepted: a
/// future YAML adapter must produce the same normalized dictionary and schema
/// errors before a profile reaches the runtime.
@interface IDHProfileLoader : NSObject

+ (nullable NSDictionary *)loadProfileAtURL:(NSURL *)url error:(NSError **)error;
+ (BOOL)validateProfile:(NSDictionary *)profile error:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
