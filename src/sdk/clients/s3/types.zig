pub const MetadataDirective = enum {
    COPY,
    REPLACE,
};
pub const TaggingDirective = enum {
    COPY,
    REPLACE,
};

pub const ObjectCannedAcl = enum {
    private,
    @"public-read",
    @"public-read-write",
    @"authenticated-read",
    @"aws-exec-read",
    @"bucket-owner-read",
    @"bucket-owner-full-control",
};

pub const StorageClass = enum {
    STANDARD,
    REDUCED_REDUNDANCY,
    STANDARD_IA,
    ONEZONE_IA,
    INTELLIGENT_TIERING,
    GLACIER,
    DEEP_ARCHIVE,
    OUTPOSTS,
    GLACIER_IR,
    SNOW,
    EXPRESS_ONEZONE,
};

pub const RequestPayer = enum { requester };

pub const OptionlBucketAttributes = enum { RestoreStatus };

pub const EncodingType = enum { url };

pub const ChecksumAlgorithm = enum {
    CRC32,
    CRC32C,
    SHA1,
    SHA256,
    CRC64NVME,
};

pub const ChecksumType = enum {
    COMPOSITE,
    FULL_OBJECT,
};

pub const ObjectLockMode = enum {
    GOVERNANCE,
    COMPLIANCE,
};

pub const ObjectLockLegalHold = enum {
    ON,
    OFF,
};

pub const ServerSideEncryption = enum {
    AES256,
    @"aws:kms",
    @"aws:kms:dsse",
};
