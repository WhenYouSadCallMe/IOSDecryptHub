#import "IDHProfileLoader.h"

static NSError *IDHProfileError(NSString *message) {
    return [NSError errorWithDomain:@"IOSDecryptHub.Profile"
                               code:1
                           userInfo:@{NSLocalizedDescriptionKey: message}];
}

@implementation IDHProfileLoader

+ (NSDictionary *)loadProfileAtURL:(NSURL *)url error:(NSError **)error {
    if (!url.isFileURL) {
        if (error) *error = IDHProfileError(@"profile URL must be a local file");
        return nil;
    }
    NSData *data = [NSData dataWithContentsOfURL:url options:0 error:error];
    if (!data) return nil;
    id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:error];
    if (![object isKindOfClass:[NSDictionary class]]) {
        if (error) *error = IDHProfileError(@"profile root must be an object");
        return nil;
    }
    if (![self validateProfile:object error:error]) return nil;
    return object;
}

+ (BOOL)validateProfile:(NSDictionary *)profile error:(NSError **)error {
    if (![profile isKindOfClass:[NSDictionary class]]) {
        if (error) *error = IDHProfileError(@"profile must be an object");
        return NO;
    }
    NSNumber *version = profile[@"schemaVersion"];
    NSString *name = profile[@"name"];
    NSArray *hooks = profile[@"hooks"];
    if (![version isKindOfClass:[NSNumber class]] || version.integerValue != 1) {
        if (error) *error = IDHProfileError(@"unsupported or missing schemaVersion");
        return NO;
    }
    if (![name isKindOfClass:[NSString class]] || !name.length) {
        if (error) *error = IDHProfileError(@"profile name is required");
        return NO;
    }
    if (![hooks isKindOfClass:[NSArray class]]) {
        if (error) *error = IDHProfileError(@"hooks must be an array");
        return NO;
    }
    NSMutableSet *ids = [NSMutableSet setWithCapacity:hooks.count];
    NSSet *types = [NSSet setWithObjects:@"objc", @"c-import", @"swift-symbol", @"js", @"notification", nil];
    for (id raw in hooks) {
        if (![raw isKindOfClass:[NSDictionary class]]) {
            if (error) *error = IDHProfileError(@"each hook must be an object");
            return NO;
        }
        NSDictionary *hook = raw;
        NSString *identifier = hook[@"id"];
        NSString *type = hook[@"type"];
        NSDictionary *target = hook[@"target"];
        NSNumber *sampleRate = hook[@"sampleRate"];
        if (![identifier isKindOfClass:[NSString class]] || !identifier.length || [ids containsObject:identifier]) {
            if (error) *error = IDHProfileError(@"hook ids must be non-empty and unique");
            return NO;
        }
        [ids addObject:identifier];
        if (![type isKindOfClass:[NSString class]] || ![types containsObject:type]) {
            if (error) *error = IDHProfileError([NSString stringWithFormat:@"unsupported hook type: %@", type ?: @"<missing>"]);
            return NO;
        }
        if (sampleRate && (sampleRate.doubleValue < 0 || sampleRate.doubleValue > 1)) {
            if (error) *error = IDHProfileError(@"sampleRate must be between 0 and 1");
            return NO;
        }
        if (![target isKindOfClass:[NSDictionary class]]) {
            if (error) *error = IDHProfileError(@"hook target is required");
            return NO;
        }
        NSString *required = nil;
        if ([type isEqualToString:@"objc"]) {
            if (![target[@"class"] isKindOfClass:[NSString class]] || ![target[@"class"] length]) required = @"target.class";
            else if (![target[@"selector"] isKindOfClass:[NSString class]] || ![target[@"selector"] length]) required = @"target.selector";
        } else if ([type isEqualToString:@"c-import"] || [type isEqualToString:@"swift-symbol"]) {
            if (![target[@"symbol"] isKindOfClass:[NSString class]] || ![target[@"symbol"] length]) required = @"target.symbol";
        } else if ([type isEqualToString:@"js"]) {
            if (![target[@"script"] isKindOfClass:[NSString class]] || ![target[@"script"] length]) required = @"target.script";
        } else if ([type isEqualToString:@"notification"]) {
            if (![target[@"image"] isKindOfClass:[NSString class]] || ![target[@"image"] length]) required = @"target.image";
        }
        if (required) {
            if (error) *error = IDHProfileError([NSString stringWithFormat:@"%@ is required for %@", required, type]);
            return NO;
        }
    }
    return YES;
}

@end
