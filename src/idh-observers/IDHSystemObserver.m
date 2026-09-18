#import "IDHSystemObserver.h"

@implementation IDHSystemObserver

- (BOOL)recordEnvironmentQuery:(NSString *)name category:(NSString *)category valueSummary:(NSDictionary *)valueSummary error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"system" operation:@"environment.query" bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"system-observer";
    event.arguments = @{ @"name": name ?: @"", @"category": category ?: @"" };
    event.result = valueSummary ?: @{};
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

- (BOOL)recordImageLoad:(NSString *)imagePath slide:(intptr_t)slide error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"system" operation:@"dyld.image" bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"dyld";
    event.arguments = @{ @"image": imagePath ?: @"", @"slide": [NSString stringWithFormat:@"0x%llx", (unsigned long long)slide] };
    event.sensitivity = IDHEventSensitivityPublic;
    return [self recordEvent:event error:error];
}

@end
