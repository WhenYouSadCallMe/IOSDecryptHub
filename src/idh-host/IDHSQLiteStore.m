#import "IDHSQLiteStore.h"

#import <sqlite3.h>

static NSError *IDHSQLiteError(sqlite3 *database, NSString *fallback) {
    const char *message = database ? sqlite3_errmsg(database) : NULL;
    return [NSError errorWithDomain:@"IOSDecryptHub.SQLite"
                                code:1
                            userInfo:@{NSLocalizedDescriptionKey: message ? [NSString stringWithUTF8String:message] : fallback}];
}

@interface IDHSQLiteStore ()
@property(nonatomic) sqlite3 *database;
@property(nonatomic, strong) NSLock *lock;
@property(nonatomic, readwrite, getter=isClosed) BOOL closed;
@end

@implementation IDHSQLiteStore

- (instancetype)initWithURL:(NSURL *)url error:(NSError **)error {
    if (!url.isFileURL) {
        if (error) *error = IDHSQLiteError(NULL, @"SQLite URL must be a local file");
        return nil;
    }
    self = [super init];
    if (!self) return nil;
    _lock = [[NSLock alloc] init];
    int result = sqlite3_open_v2(url.path.fileSystemRepresentation, &_database,
                                 SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (result != SQLITE_OK) {
        if (error) *error = IDHSQLiteError(_database, @"unable to open SQLite database");
        if (_database) sqlite3_close(_database);
        return nil;
    }
    const char *schema =
        "PRAGMA journal_mode=WAL;"
        "CREATE TABLE IF NOT EXISTS events ("
        "event_id TEXT PRIMARY KEY, timestamp REAL NOT NULL, session_id TEXT, flow_id TEXT, request_id TEXT, "
        "type TEXT NOT NULL, operation TEXT NOT NULL, payload TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS events_flow_idx ON events(flow_id, timestamp);"
        "CREATE INDEX IF NOT EXISTS events_request_idx ON events(request_id, timestamp);"
        "CREATE INDEX IF NOT EXISTS events_type_idx ON events(type, timestamp);";
    char *message = NULL;
    result = sqlite3_exec(_database, schema, NULL, NULL, &message);
    if (result != SQLITE_OK) {
        if (error) *error = [NSError errorWithDomain:@"IOSDecryptHub.SQLite" code:2 userInfo:@{NSLocalizedDescriptionKey: message ? [NSString stringWithUTF8String:message] : @"schema initialization failed"}];
        sqlite3_free(message);
        sqlite3_close(_database);
        _database = NULL;
        return nil;
    }
    return self;
}

- (BOOL)appendEvent:(IDHEvent *)event error:(NSError **)error {
    if (!event) {
        if (error) *error = IDHSQLiteError(_database, @"event is required");
        return NO;
    }
    NSData *json = [event JSONData:error];
    if (!json) return NO;
    NSString *payload = [[NSString alloc] initWithData:json encoding:NSUTF8StringEncoding];
    if (!payload) {
        if (error) *error = IDHSQLiteError(_database, @"event JSON is not UTF-8");
        return NO;
    }
    [_lock lock];
    if (_closed || !_database) {
        [_lock unlock];
        if (error) *error = IDHSQLiteError(NULL, @"SQLite store is closed");
        return NO;
    }
    const char *sql = "INSERT OR REPLACE INTO events(event_id,timestamp,session_id,flow_id,request_id,type,operation,payload) VALUES(?,?,?,?,?,?,?,?)";
    sqlite3_stmt *statement = NULL;
    int result = sqlite3_prepare_v2(_database, sql, -1, &statement, NULL);
    if (result == SQLITE_OK) {
        sqlite3_bind_text(statement, 1, event.eventID.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_double(statement, 2, event.timestamp.timeIntervalSince1970);
        sqlite3_bind_text(statement, 3, event.sessionID.UTF8String ?: "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 4, event.flowID.UTF8String ?: "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 5, event.requestID.UTF8String ?: "", -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 6, event.type.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 7, event.operation.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(statement, 8, payload.UTF8String, -1, SQLITE_TRANSIENT);
        result = sqlite3_step(statement);
    }
    if (statement) sqlite3_finalize(statement);
    BOOL ok = result == SQLITE_DONE;
    if (!ok && error) *error = IDHSQLiteError(_database, @"SQLite insert failed");
    [_lock unlock];
    return ok;
}

- (NSArray<NSDictionary *> *)queryWithFlowID:(NSString *)flowID requestID:(NSString *)requestID type:(NSString *)type limit:(NSUInteger)limit error:(NSError **)error {
    if (limit == 0 || limit > 10000) limit = 1000;
    [_lock lock];
    if (_closed || !_database) {
        [_lock unlock];
        if (error) *error = IDHSQLiteError(NULL, @"SQLite store is closed");
        return @[];
    }
    NSMutableArray *conditions = [NSMutableArray array];
    if (flowID.length) [conditions addObject:@"flow_id = ?"];
    if (requestID.length) [conditions addObject:@"request_id = ?"];
    if (type.length) [conditions addObject:@"type = ?"];
    NSString *where = conditions.count ? [NSString stringWithFormat:@"WHERE %@", [conditions componentsJoinedByString:@" AND "]] : @"";
    NSString *sql = [NSString stringWithFormat:@"SELECT payload FROM events %@ ORDER BY timestamp ASC LIMIT ?", where];
    sqlite3_stmt *statement = NULL;
    int result = sqlite3_prepare_v2(_database, sql.UTF8String, -1, &statement, NULL);
    NSMutableArray *events = [NSMutableArray array];
    if (result == SQLITE_OK) {
        int parameter = 1;
        if (flowID.length) sqlite3_bind_text(statement, parameter++, flowID.UTF8String, -1, SQLITE_TRANSIENT);
        if (requestID.length) sqlite3_bind_text(statement, parameter++, requestID.UTF8String, -1, SQLITE_TRANSIENT);
        if (type.length) sqlite3_bind_text(statement, parameter++, type.UTF8String, -1, SQLITE_TRANSIENT);
        sqlite3_bind_int(statement, parameter, (int)limit);
        while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
            const unsigned char *text = sqlite3_column_text(statement, 0);
            if (!text) continue;
            NSData *data = [NSData dataWithBytes:text length:(NSUInteger)sqlite3_column_bytes(statement, 0)];
            NSDictionary *object = [NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
            if ([object isKindOfClass:[NSDictionary class]]) [events addObject:object];
        }
    }
    if (statement) sqlite3_finalize(statement);
    BOOL failed = result != SQLITE_DONE && result != SQLITE_OK;
    if (failed && error) *error = IDHSQLiteError(_database, @"SQLite query failed");
    [_lock unlock];
    return events;
}

- (void)close {
    [_lock lock];
    if (!_closed) {
        if (_database) sqlite3_close(_database);
        _database = NULL;
        _closed = YES;
    }
    [_lock unlock];
}

- (void)dealloc {
    [self close];
}

@end
