#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Produces metadata only; it never stores a complete input buffer in the
/// result dictionary.
FOUNDATION_EXPORT NSDictionary *IDHProfileData(NSData *data);
FOUNDATION_EXPORT double IDHShannonEntropy(NSData *data);

NS_ASSUME_NONNULL_END
