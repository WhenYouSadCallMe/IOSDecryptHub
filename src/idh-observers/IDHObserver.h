#import <Foundation/Foundation.h>

#import "IDHEvent.h"

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, IDHObserverMode) {
    IDHObserverModeRecordOnly = 0,
    IDHObserverModeExtended = 1,
    IDHObserverModeLab = 2,
};

@protocol IDHObserver <NSObject>

@property(nonatomic, copy, readonly) NSString *observerID;
@property(nonatomic, readonly) IDHObserverMode mode;

- (BOOL)startWithOptions:(NSDictionary *)options error:(NSError **)error;
- (void)stop;
- (BOOL)isRunning;

@end

/// Coordinates record-only observers. The coordinator does not discover,
/// inject or swizzle target code; platform adapters must explicitly opt in.
@interface IDHObserverCoordinator : NSObject

- (void)registerObserver:(id<IDHObserver>)observer;
- (BOOL)startObserver:(NSString *)observerID options:(NSDictionary *)options error:(NSError **)error;
- (void)stopObserver:(NSString *)observerID;
- (NSArray<NSString *> *)observerIDs;

@end

NS_ASSUME_NONNULL_END
