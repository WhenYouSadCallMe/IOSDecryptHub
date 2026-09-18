#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface IDHImageInfo : NSObject <NSCopying>

@property(nonatomic, copy) NSString *name;
@property(nonatomic, copy, nullable) NSString *path;
@property(nonatomic) uintptr_t headerAddress;
@property(nonatomic) intptr_t slide;
@property(nonatomic, copy, nullable) NSString *uuid;

- (NSDictionary *)dictionaryRepresentation;

@end

/// Read-only dyld image inventory. It observes the current process image list;
/// it does not install callbacks, rewrite symbols or modify memory.
@interface IDHMachO : NSObject

+ (NSArray<IDHImageInfo *> *)loadedImages;
+ (nullable IDHImageInfo *)imageContainingAddress:(uintptr_t)address;
+ (nullable NSNumber *)idaAddressForRuntimeAddress:(uintptr_t)address slide:(intptr_t)slide;

@end

NS_ASSUME_NONNULL_END
