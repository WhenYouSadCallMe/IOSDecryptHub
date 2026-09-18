#import <Foundation/Foundation.h>
#include <stdint.h>
#include <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

FOUNDATION_EXPORT NSInteger const IDHEventSchemaVersion;

typedef NS_ENUM(NSInteger, IDHEventSensitivity) {
    IDHEventSensitivityPublic = 0,
    IDHEventSensitivityMasked = 1,
    IDHEventSensitivitySecret = 2,
};

/// Transport-neutral event shared by native observers, WebKit adapters and
/// the desktop collector. It contains summaries by default; observers should
/// never put an unredacted credential in arguments/result automatically.
@interface IDHEvent : NSObject <NSCopying>

@property(nonatomic, copy) NSString *eventID;
@property(nonatomic, copy, nullable) NSString *sessionID;
@property(nonatomic, strong) NSDate *timestamp;
@property(nonatomic, copy, nullable) NSString *bundleID;
@property(nonatomic) pid_t pid;
@property(nonatomic) uint64_t tid;
@property(nonatomic, copy, nullable) NSString *image;
@property(nonatomic, copy, nullable) NSString *aslrSlide;
@property(nonatomic, copy, nullable) NSString *flowID;
@property(nonatomic, copy, nullable) NSString *requestID;
@property(nonatomic, copy, nullable) NSString *parentEventID;
@property(nonatomic, copy) NSString *layer;
@property(nonatomic, copy) NSString *type;
@property(nonatomic, copy) NSString *operation;
@property(nonatomic, copy, nullable) id arguments;
@property(nonatomic, copy, nullable) id result;
@property(nonatomic, copy) NSArray<NSDictionary *> *nativeStack;
@property(nonatomic, copy) NSArray<NSDictionary *> *jsStack;
@property(nonatomic, copy) NSArray<NSDictionary *> *valueRefs;
@property(nonatomic, copy) NSArray<NSString *> *tags;
@property(nonatomic) double confidence;
@property(nonatomic, copy, nullable) NSDictionary *evidence;
@property(nonatomic, copy, nullable) NSDictionary *analysis;
@property(nonatomic) IDHEventSensitivity sensitivity;
@property(nonatomic) BOOL dropped;

- (instancetype)initWithType:(NSString *)type
                    operation:(NSString *)operation
                    bundleID:(nullable NSString *)bundleID;

- (NSDictionary *)dictionaryRepresentation;
- (nullable NSData *)JSONData:(NSError **)error;
- (BOOL)validate:(NSError **)error;

@end

NS_ASSUME_NONNULL_END
