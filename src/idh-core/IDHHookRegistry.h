#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Thread-safe registry for declarative observer specifications. It only
/// tracks validated configuration and runtime state; adapter modules decide
/// how a signed, authorized target is observed.
@interface IDHHookRegistry : NSObject

- (BOOL)registerHook:(NSDictionary *)hook error:(NSError **)error;
- (BOOL)installProfile:(NSDictionary *)profile error:(NSError **)error;
- (BOOL)setEnabled:(BOOL)enabled forHookID:(NSString *)hookID error:(NSError **)error;
- (BOOL)unregisterHookID:(NSString *)hookID error:(NSError **)error;
- (nullable NSDictionary *)entryForHookID:(NSString *)hookID;
- (NSArray<NSDictionary *> *)snapshot;

@end

NS_ASSUME_NONNULL_END
