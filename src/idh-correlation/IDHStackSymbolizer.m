#import "IDHStackSymbolizer.h"

NSDictionary *IDHNormalizeStackFrame(NSDictionary *frame, uintptr_t slide) {
    NSNumber *addressValue = frame[@"address"];
    if (![addressValue isKindOfClass:[NSNumber class]]) return @{ @"unresolved": @YES, @"reason": @"address is missing" };
    uintptr_t address = addressValue.unsignedLongLongValue;
    if (address < slide) return @{ @"unresolved": @YES, @"reason": @"address is below ASLR slide", @"address": addressValue };
    NSMutableDictionary *result = [frame mutableCopy] ?: [NSMutableDictionary dictionary];
    result[@"idaAddress"] = @(address - slide);
    result[@"normalized"] = [NSString stringWithFormat:@"0x%llx", (unsigned long long)(address - slide)];
    return result;
}
