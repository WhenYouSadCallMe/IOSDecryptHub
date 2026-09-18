#import "IDHStorageObserver.h"

#import "IDHAnalysisProfiler.h"

@implementation IDHStorageObserver

- (BOOL)recordKeychainOperation:(NSString *)operation service:(NSString *)service account:(NSString *)account result:(NSDictionary *)result error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"storage" operation:operation bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"keychain";
    event.arguments = @{
        @"service": service ?: @"",
        @"account": account ?: @"",
    };
    event.result = result ?: @{};
    event.sensitivity = IDHEventSensitivitySecret;
    return [self recordEvent:event error:error];
}

- (BOOL)recordFileOperation:(NSString *)operation path:(NSString *)path result:(NSData *)result error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"storage" operation:operation bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"posix-file";
    event.arguments = @{ @"path": path ?: @"" };
    event.result = result ? IDHProfileData(result) : @{};
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

- (BOOL)recordSQLiteOperation:(NSString *)operation database:(NSString *)database sql:(NSString *)sql result:(NSDictionary *)result error:(NSError **)error {
    IDHEvent *event = [[IDHEvent alloc] initWithType:@"storage" operation:operation bundleID:NSBundle.mainBundle.bundleIdentifier];
    event.layer = @"sqlite";
    event.arguments = @{
        @"database": database ?: @"",
        @"sql": sql ?: @"",
    };
    event.result = result ?: @{};
    event.sensitivity = IDHEventSensitivityMasked;
    return [self recordEvent:event error:error];
}

@end
