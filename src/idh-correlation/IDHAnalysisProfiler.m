#import "IDHAnalysisProfiler.h"

#import <CommonCrypto/CommonDigest.h>
#import <math.h>
#import <string.h>

double IDHShannonEntropy(NSData *data) {
    if (!data.length) return 0;
    NSUInteger counts[256] = {0};
    const uint8_t *bytes = data.bytes;
    for (NSUInteger index = 0; index < data.length; index++) counts[bytes[index]]++;
    double result = 0;
    for (NSUInteger index = 0; index < 256; index++) {
        if (!counts[index]) continue;
        double probability = (double)counts[index] / (double)data.length;
        result -= probability * log2(probability);
    }
    return result;
}

static NSString *IDHMagic(NSData *data) {
    if (data.length >= 2 && ((const uint8_t *)data.bytes)[0] == 0x1f && ((const uint8_t *)data.bytes)[1] == 0x8b) return @"gzip";
    if (data.length >= 4 && memcmp(data.bytes, "PK\x03\x04", 4) == 0) return @"zip";
    if (data.length >= 4 && memcmp(data.bytes, "\x7fELF", 4) == 0) return @"elf";
    if (data.length >= 2 && ((const uint8_t *)data.bytes)[0] == 0x30 && ((const uint8_t *)data.bytes)[1] >= 0x80) return @"asn1";
    return @"";
}

static BOOL IDHPrintable(NSData *data) {
    if (!data.length) return NO;
    const uint8_t *bytes = data.bytes;
    NSUInteger printable = 0;
    for (NSUInteger index = 0; index < data.length; index++) {
        uint8_t value = bytes[index];
        if (value == '\n' || value == '\r' || value == '\t' || (value >= 0x20 && value < 0x7f)) printable++;
    }
    return (double)printable / (double)data.length >= 0.85;
}

NSDictionary *IDHProfileData(NSData *data) {
    if (!data) data = [NSData data];
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++) [hash appendFormat:@"%02x", digest[index]];
    NSString *magic = IDHMagic(data);
    NSString *encoding = magic.length ? magic : (IDHPrintable(data) ? @"utf8" : @"binary");
    return @{
        @"length": @(data.length),
        @"sha256": hash,
        @"entropy": @(IDHShannonEntropy(data)),
        @"magicBytes": magic,
        @"encoding": encoding,
    };
}
