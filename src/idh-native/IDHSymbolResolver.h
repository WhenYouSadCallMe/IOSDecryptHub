#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Read-only symbol lookup for the current process. It does not rebind GOT
/// entries or install a trampoline.
@interface IDHSymbolResolver : NSObject

+ (nullable NSNumber *)addressForSymbol:(NSString *)symbol;
+ (NSString *)displayNameForSymbol:(NSString *)symbol;

@end

NS_ASSUME_NONNULL_END
