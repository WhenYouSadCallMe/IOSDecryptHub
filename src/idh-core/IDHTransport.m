#import "IDHTransport.h"

@implementation IDHJSONLTransport {
    NSFileHandle *_handle;
    NSLock *_lock;
    uint64_t _written;
    uint64_t _bytes;
    uint64_t _failed;
    BOOL _closed;
}

- (instancetype)initWithURL:(NSURL *)url error:(NSError **)error {
    if (!url.isFileURL) {
        if (error) *error = [NSError errorWithDomain:@"IOSDecryptHub.Transport"
                                                code:1
                                            userInfo:@{NSLocalizedDescriptionKey: @"JSONL URL must be a local file"}];
        return nil;
    }
    [[NSFileManager defaultManager] createFileAtPath:url.path contents:nil attributes:nil];
    self = [super init];
    if (!self) return nil;
    _handle = [NSFileHandle fileHandleForWritingToURL:url error:error];
    if (!_handle) return nil;
    [_handle seekToEndReturningError:error];
    if (error && *error) return nil;
    _lock = [[NSLock alloc] init];
    return self;
}

- (BOOL)appendEvent:(IDHEvent *)event error:(NSError **)error {
    NSError *jsonError = nil;
    NSData *json = [event JSONData:&jsonError];
    if (!json) {
        if (error) *error = jsonError;
        [_lock lock]; _failed++; [_lock unlock];
        return NO;
    }
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    [_lock lock];
    if (_closed) {
        [_lock unlock];
        if (error) *error = [NSError errorWithDomain:@"IOSDecryptHub.Transport"
                                                 code:2
                                             userInfo:@{NSLocalizedDescriptionKey: @"transport is closed"}];
        return NO;
    }
    NSError *writeError = nil;
    BOOL ok = [_handle writeData:line error:&writeError];
    if (ok) { _written++; _bytes += line.length; } else { _failed++; }
    [_lock unlock];
    if (!ok && error) *error = writeError;
    return ok;
}

- (BOOL)flush:(NSError **)error {
    [_lock lock];
    BOOL ok = !_closed;
    NSError *flushError = nil;
    if (ok) ok = [_handle synchronizeAndReturnError:&flushError];
    [_lock unlock];
    if (!ok && error) *error = flushError ?: [NSError errorWithDomain:@"IOSDecryptHub.Transport" code:3 userInfo:nil];
    return ok;
}

- (void)close {
    [_lock lock];
    if (!_closed) {
        [_handle synchronizeFile];
        [_handle closeFile];
        _closed = YES;
    }
    [_lock unlock];
}

- (NSDictionary *)statistics {
    [_lock lock];
    NSDictionary *result = @{@"written": @(_written), @"bytes": @(_bytes), @"failed": @(_failed), @"closed": @(_closed)};
    [_lock unlock];
    return result;
}

@end
