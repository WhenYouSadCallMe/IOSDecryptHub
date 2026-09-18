#import "IDHSymbolResolver.h"

#import <dlfcn.h>

@implementation IDHSymbolResolver

+ (NSNumber *)addressForSymbol:(NSString *)symbol {
    if (!symbol.length) return nil;
    void *address = dlsym(RTLD_DEFAULT, symbol.UTF8String);
    return address ? @((uintptr_t)address) : nil;
}

+ (NSString *)displayNameForSymbol:(NSString *)symbol {
    if (!symbol.length) return @"";
    NSString *name = [symbol copy];
    if ([name hasPrefix:@"_$s"]) name = [name substringFromIndex:2];
    if ([name hasPrefix:@"$s"]) return [name substringFromIndex:2];
    if ([name hasPrefix:@"$S"]) return [name substringFromIndex:2];
    return name;
}

@end
