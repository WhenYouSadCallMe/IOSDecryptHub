#import "IDHMachO.h"

#import <mach-o/dyld.h>
#import <mach-o/loader.h>

@implementation IDHImageInfo

- (id)copyWithZone:(NSZone *)zone {
    IDHImageInfo *copy = [[[self class] allocWithZone:zone] init];
    copy.name = self.name;
    copy.path = self.path;
    copy.headerAddress = self.headerAddress;
    copy.slide = self.slide;
    copy.uuid = self.uuid;
    return copy;
}

- (NSDictionary *)dictionaryRepresentation {
    NSMutableDictionary *result = [@{
        @"name": self.name ?: @"",
        @"headerAddress": [NSString stringWithFormat:@"0x%llx", (unsigned long long)self.headerAddress],
        @"slide": [NSString stringWithFormat:@"0x%llx", (unsigned long long)self.slide],
    } mutableCopy];
    if (self.path) result[@"path"] = self.path;
    if (self.uuid) result[@"uuid"] = self.uuid;
    return result;
}

@end

static NSString *IDHUUIDForHeader(const struct mach_header *header) {
    if (!header) return nil;
    BOOL is64 = header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64;
    const uint8_t *cursor = (const uint8_t *)header + (is64 ? sizeof(struct mach_header_64) : sizeof(struct mach_header));
    uint32_t count = is64 ? ((const struct mach_header_64 *)header)->ncmds : header->ncmds;
    for (uint32_t index = 0; index < count; index++) {
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < sizeof(struct load_command)) break;
        if (command->cmd == LC_UUID && command->cmdsize >= sizeof(struct uuid_command)) {
            const struct uuid_command *uuid = (const struct uuid_command *)command;
            const uint8_t *bytes = uuid->uuid;
            return [NSString stringWithFormat:@"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                    bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]];
        }
        cursor += command->cmdsize;
    }
    return nil;
}

@implementation IDHMachO

+ (NSArray<IDHImageInfo *> *)loadedImages {
    uint32_t count = _dyld_image_count();
    NSMutableArray *images = [NSMutableArray arrayWithCapacity:count];
    for (uint32_t index = 0; index < count; index++) {
        const struct mach_header *header = _dyld_get_image_header(index);
        if (!header) continue;
        IDHImageInfo *info = [[IDHImageInfo alloc] init];
        info.name = [NSString stringWithUTF8String:_dyld_get_image_name(index) ?: ""] ?: @"";
        info.path = info.name;
        info.headerAddress = (uintptr_t)header;
        info.slide = _dyld_get_image_vmaddr_slide(index);
        info.uuid = IDHUUIDForHeader(header);
        [images addObject:info];
    }
    return images;
}

+ (IDHImageInfo *)imageContainingAddress:(uintptr_t)address {
    for (IDHImageInfo *image in [self loadedImages]) {
        if (address >= image.headerAddress) return image;
    }
    return nil;
}

+ (NSNumber *)idaAddressForRuntimeAddress:(uintptr_t)address slide:(intptr_t)slide {
    if (slide < 0) {
        uintptr_t magnitude = (uintptr_t)(-(slide + 1)) + 1;
        if (address > UINTPTR_MAX - magnitude) return nil;
        return @(address + magnitude);
    }
    uintptr_t unsignedSlide = (uintptr_t)slide;
    if (address < unsignedSlide) return nil;
    return @(address - unsignedSlide);
}

@end
