#include "rflac.h"

#include <stdlib.h>
#include <assert.h>
#include <string.h> /* For memset() */


/*
This is something that could be optimized to good effect. Use the CPUs built-in CLZ instruction.
*/
static rflac_uint32 rflac_clz_64(rflac_uint64 x)
{
    rflac_uint32 n;
    rflac_uint32 clz_table_4[] = {
        0,
        4,
        3, 3,
        2, 2, 2, 2,
        1, 1, 1, 1, 1, 1, 1, 1
    };

    if (x == 0) {
        return sizeof(x)*8;
    }

    n = clz_table_4[x >> (sizeof(x)*8 - 4)];
    if (n == 0) {
        if ((x & ((rflac_uint64)0xFFFFFFFF << 32)) == 0) { n  = 32; x <<= 32; }
        if ((x & ((rflac_uint64)0xFFFF0000 << 32)) == 0) { n += 16; x <<= 16; }
        if ((x & ((rflac_uint64)0xFF000000 << 32)) == 0) { n += 8;  x <<= 8;  }
        if ((x & ((rflac_uint64)0xF0000000 << 32)) == 0) { n += 4;  x <<= 4;  }
        n += clz_table_4[x >> (sizeof(x)*8 - 4)];
    }

    return n - 1;
}

static rflac_uint32 rflac_swap_endian_32(rflac_uint32 x)
{
    return ((x & 0xFF000000) >> 24) |
           ((x & 0x00FF0000) >>  8) |
           ((x & 0x0000FF00) <<  8) |
           ((x & 0x000000FF) << 24);
}

static rflac_uint64 rflac_swap_endian_64(rflac_uint64 x)
{
    /* Weird "<< 32" bitshift is required for C89 because it doesn't support 64-bit constants. Should be optimized out by a good compiler. */
    return ((x & ((rflac_uint64)0xFF000000 << 32)) >> 56) |
           ((x & ((rflac_uint64)0x00FF0000 << 32)) >> 40) |
           ((x & ((rflac_uint64)0x0000FF00 << 32)) >> 24) |
           ((x & ((rflac_uint64)0x000000FF << 32)) >>  8) |
           ((x & ((rflac_uint64)0xFF000000      )) <<  8) |
           ((x & ((rflac_uint64)0x00FF0000      )) << 24) |
           ((x & ((rflac_uint64)0x0000FF00      )) << 40) |
           ((x & ((rflac_uint64)0x000000FF      )) << 56);
}

static rflac_bool8 rflac_is_little_endian()
{
#if defined(__i386) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_X64)
    return 1;
#elif defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN) && __BYTE_ORDER == __LITTLE_ENDIAN
    return 0;
#else
    int n = 1;
    return (*(char*)&n) == 1;
#endif
}

static rflac_uint32 rflac_be2host_32(rflac_uint32 x)
{
    if (rflac_is_little_endian()) {
        return rflac_swap_endian_32(x);
    }

    return x;
}

static rflac_uint64 rflac_be2host_64(rflac_uint64 x)
{
    if (rflac_is_little_endian()) {
        return rflac_swap_endian_64(x);
    }

    return x;
}



/**************************************************************************************************

Bit Stream

This is taken from dr_flac with a few adjustments. For implementation simplicity, it always uses a
64-bit cache rather than choosing between 32-bit and 64-bit depending on the architecture. For an
optimal solution you would want to use a 32-bit cache on 32-bit architectures.

The bit stream is not necessary for understanding the FLAC format. It's just a tool to help with
reading data that is not byte-clean. You do not need to understand the implementation details of
the bit stream in order to understand the FLAC format so you can skip this section if you're just
wanting to learn about the FLAC format.

**************************************************************************************************/
typedef struct
{
    const unsigned char* pData8;
    size_t dataSize;
    size_t bytesRead;


    /*
    Indicates whether or not the bistream is in a reset state. This is required in case rflac_bs_get_bytes_consumed() is
    called on a freshly initialized bitstream. It will use consumedBits to determine how many bytes in the L1 cache has
    been consumed, however this will be initialized to RFLAC_CACHE_L1_SIZE_BYTES() which would result in an incorrect result.
    */
    rflac_bool8 isReset;

    /*
    The number of unaligned bytes in the L2 cache. This will always be 0 until the end of the stream is hit. At the end of the
    stream there will be a number of bytes that don't cleanly fit in an L1 cache line, so we use this variable to know whether
    or not the bistreamer needs to run on a slower path to read those last bytes. This will never be more than sizeof(rflac_uint64).
    */
    size_t unalignedByteCount;

    /* The content of the unaligned bytes. */
    rflac_uint64 unalignedCache;

    /* The index of the next valid cache line in the "L2" cache. */
    rflac_uint32 nextL2Line;

    /* The number of bits that have been consumed by the cache. This is used to determine how many valid bits are remaining. */
    rflac_uint32 consumedBits;

    /*
    The cached data which was most recently read from the client. There are two levels of cache. Data flows as such:
    Client -> L2 -> L1. The L2 -> L1 movement is aligned and runs on a fast path in just a few instructions.
    */
    rflac_uint64 cacheL2[4096/sizeof(rflac_uint64)];
    rflac_uint64 cache;
} rflac_bs;


#define RFLAC_CACHE_L1_SIZE_BYTES(bs)                      (sizeof((bs)->cache))
#define RFLAC_CACHE_L1_SIZE_BITS(bs)                       (sizeof((bs)->cache)*8)
#define RFLAC_CACHE_L1_BITS_REMAINING(bs)                  (RFLAC_CACHE_L1_SIZE_BITS(bs) - (bs)->consumedBits)
#define RFLAC_CACHE_L1_SELECTION_MASK(_bitCount)           (~((~(rflac_uint64)0) >> (_bitCount)))
#define RFLAC_CACHE_L1_SELECTION_SHIFT(bs, _bitCount)      (RFLAC_CACHE_L1_SIZE_BITS(bs) - (_bitCount))
#define RFLAC_CACHE_L1_SELECT(bs, _bitCount)               (((bs)->cache) & RFLAC_CACHE_L1_SELECTION_MASK(_bitCount))
#define RFLAC_CACHE_L1_SELECT_AND_SHIFT(bs, _bitCount)     (RFLAC_CACHE_L1_SELECT((bs), (_bitCount)) >>  RFLAC_CACHE_L1_SELECTION_SHIFT((bs), (_bitCount)))
#define RFLAC_CACHE_L1_SELECT_AND_SHIFT_SAFE(bs, _bitCount)(RFLAC_CACHE_L1_SELECT((bs), (_bitCount)) >> (RFLAC_CACHE_L1_SELECTION_SHIFT((bs), (_bitCount)) & (RFLAC_CACHE_L1_SIZE_BITS(bs)-1)))
#define RFLAC_CACHE_L2_SIZE_BYTES(bs)                      (sizeof((bs)->cacheL2))
#define RFLAC_CACHE_L2_LINE_COUNT(bs)                      (RFLAC_CACHE_L2_SIZE_BYTES(bs) / sizeof((bs)->cacheL2[0]))
#define RFLAC_CACHE_L2_LINES_REMAINING(bs)                 (RFLAC_CACHE_L2_LINE_COUNT(bs) - (bs)->nextL2Line)

static rflac_result rflac_bs_init(const void* pData, size_t dataSize, rflac_bs* bs)
{
    assert(bs != NULL);
    assert(pData != NULL);

    memset(bs, 0, sizeof(*bs));

    bs->pData8       = (const unsigned char*)pData;
    bs->dataSize     = dataSize;
    bs->bytesRead    = 0;
    bs->isReset      = RFLAC_TRUE;
    bs->nextL2Line   = RFLAC_CACHE_L2_LINE_COUNT(bs);   /* <-- This clears the L2 cache. */
    bs->consumedBits = RFLAC_CACHE_L1_SIZE_BITS(bs);    /* <-- This clears the L1 cache. */

    return RFLAC_SUCCESS;
}

static rflac_result rflac_bs_reload_l1_cache_from_l2(rflac_bs* bs)
{
    size_t bytesRead;
    size_t alignedL1LineCount;

    /* TODO: This can be optimized and simpified. There's no need to read from the client because the data itself *is* the L2 cache. */

    /* Fast path. Try loading straight from L2. */
    if (bs->nextL2Line < RFLAC_CACHE_L2_LINE_COUNT(bs)) {
        bs->cache = bs->cacheL2[bs->nextL2Line++];
        return RFLAC_SUCCESS;
    }

    /*
    If we get here it means we've run out of data in the L2 cache. We'll need to fetch more from the client, if there's
    any left.
    */
    if (bs->unalignedByteCount > 0) {
        return RFLAC_NOT_ENOUGH_DATA;   /* If we have any unaligned bytes it means there's no more aligned bytes left in the client. */
    }

    {
        size_t bytesToRead = RFLAC_CACHE_L2_SIZE_BYTES(bs);
        if (bytesToRead > (bs->dataSize - bs->bytesRead)) {
            bytesToRead = (bs->dataSize - bs->bytesRead);
        }

        memcpy(bs->cacheL2, bs->pData8 + bs->bytesRead, bytesToRead);

        bytesRead      = bytesToRead;
        bs->bytesRead += bytesToRead;
    }
    
    bs->nextL2Line = 0;
    if (bytesRead == RFLAC_CACHE_L2_SIZE_BYTES(bs)) {
        bs->cache = bs->cacheL2[bs->nextL2Line++];
        return RFLAC_SUCCESS;
    }


    /*
    If we get here it means we were unable to retrieve enough data to fill the entire L2 cache. It probably
    means we've just reached the end of the file. We need to move the valid data down to the end of the buffer
    and adjust the index of the next line accordingly. Also keep in mind that the L2 cache must be aligned to
    the size of the L1 so we'll need to seek backwards by any misaligned bytes.
    */
    alignedL1LineCount = bytesRead / RFLAC_CACHE_L1_SIZE_BYTES(bs);

    /* We need to keep track of any unaligned bytes for later use. */
    bs->unalignedByteCount = bytesRead - (alignedL1LineCount * RFLAC_CACHE_L1_SIZE_BYTES(bs));
    if (bs->unalignedByteCount > 0) {
        bs->unalignedCache = bs->cacheL2[alignedL1LineCount];
    }

    if (alignedL1LineCount > 0) {
        size_t offset = RFLAC_CACHE_L2_LINE_COUNT(bs) - alignedL1LineCount;
        size_t i;
        for (i = alignedL1LineCount; i > 0; --i) {
            bs->cacheL2[i-1 + offset] = bs->cacheL2[i-1];
        }

        bs->nextL2Line = (rflac_uint32)offset;
        bs->cache = bs->cacheL2[bs->nextL2Line++];
        return RFLAC_SUCCESS;
    } else {
        /* If we get into this branch it means we weren't able to load any L1-aligned data. */
        bs->nextL2Line = RFLAC_CACHE_L2_LINE_COUNT(bs);
        return RFLAC_NOT_ENOUGH_DATA;
    }
}

static rflac_result rflac_bs_reload_cache(rflac_bs* bs)
{
    size_t bytesRead;

    /* If we're reloading the cache it means the bitstream is no longer in a reset state. This state is required for rflac_bs_get_bytes_consumed(). Would be nice if we could remove this. */
    bs->isReset = RFLAC_FALSE;

    /* Fast path. Try just moving the next value in the L2 cache to the L1 cache. */
    if (rflac_bs_reload_l1_cache_from_l2(bs) == RFLAC_SUCCESS) {
        bs->cache = rflac_be2host_64(bs->cache);
        bs->consumedBits = 0;
        return RFLAC_SUCCESS;
    }

    /* Slow path. */

    /*
    If we get here it means we have failed to load the L1 cache from the L2. Likely we've just reached the end of the stream and the last
    few bytes did not meet the alignment requirements for the L2 cache. In this case we need to fall back to a slower path and read the
    data from the unaligned cache.
    */
    bytesRead = bs->unalignedByteCount;
    if (bytesRead == 0) {
        bs->consumedBits = RFLAC_CACHE_L1_SIZE_BITS(bs);   /* <-- The stream has been exhausted, so marked the bits as consumed. */
        return RFLAC_NOT_ENOUGH_DATA;
    }

    assert(bytesRead < RFLAC_CACHE_L1_SIZE_BYTES(bs));
    bs->consumedBits = (rflac_uint32)(RFLAC_CACHE_L1_SIZE_BYTES(bs) - bytesRead) * 8;

    bs->cache = rflac_be2host_64(bs->unalignedCache);
    bs->cache &= RFLAC_CACHE_L1_SELECTION_MASK(RFLAC_CACHE_L1_BITS_REMAINING(bs));    /* <-- Make sure the consumed bits are always set to zero. Other parts of the library depend on this property. */
    bs->unalignedByteCount = 0;     /* <-- At this point the unaligned bytes have been moved into the cache and we thus have no more unaligned bytes. */

    return RFLAC_SUCCESS;
}

static size_t rflac_bs_get_bytes_consumed(rflac_bs* bs)
{
    size_t bytesConsumed;

    /* This is total bytes taken from the buffer, minus whatever is in the L2 cache, minus the L1 cache, plus any bits that have been consumed in the L1 cache. */
    bytesConsumed = bs->bytesRead - (RFLAC_CACHE_L2_LINES_REMAINING(bs) * sizeof(bs->cacheL2[0])) - bs->unalignedByteCount;
    if (!bs->isReset) {
        bytesConsumed -= sizeof(bs->cache);
        bytesConsumed += bs->consumedBits >> 3;
    }

    return bytesConsumed;
}


static rflac_result rflac_bs_read_uint32(rflac_bs* bs, unsigned int bitCount, rflac_uint32* pResultOut)
{
    rflac_result result;

    assert(bs != NULL);
    assert(pResultOut != NULL);
    assert(bitCount > 0);
    assert(bitCount <= 32);

    if (bs->consumedBits == RFLAC_CACHE_L1_SIZE_BITS(bs)) {
        result = rflac_bs_reload_cache(bs);
        if (result != RFLAC_SUCCESS) {
            return result;
        }
    }

    if (bitCount <= RFLAC_CACHE_L1_BITS_REMAINING(bs)) {
        *pResultOut = (rflac_uint32)RFLAC_CACHE_L1_SELECT_AND_SHIFT(bs, bitCount);
        bs->consumedBits += bitCount;
        bs->cache <<= bitCount;

        return RFLAC_SUCCESS;
    } else {
        /* It straddles the cached data. It will never cover more than the next chunk. We just read the number in two parts and combine them. */
        rflac_uint32 bitCountHi = RFLAC_CACHE_L1_BITS_REMAINING(bs);
        rflac_uint32 bitCountLo = bitCount - bitCountHi;
        rflac_uint32 resultHi;

        assert(bitCountHi > 0);
        assert(bitCountHi < 32);
        resultHi = (rflac_uint32)RFLAC_CACHE_L1_SELECT_AND_SHIFT(bs, bitCountHi);

        result = rflac_bs_reload_cache(bs);
        if (result != RFLAC_SUCCESS) {
            return result;
        }
        if (bitCountLo > RFLAC_CACHE_L1_BITS_REMAINING(bs)) {
            /* This happens when we get to end of stream */
            return RFLAC_NOT_ENOUGH_DATA;
        }

        *pResultOut = (resultHi << bitCountLo) | (rflac_uint32)RFLAC_CACHE_L1_SELECT_AND_SHIFT(bs, bitCountLo);
        bs->consumedBits += bitCountLo;
        bs->cache <<= bitCountLo;
        return RFLAC_SUCCESS;
    }
}

static rflac_result rflac_bs_read_int32(rflac_bs* bs, unsigned int bitCount, rflac_int32* pResult)
{
    rflac_uint32 x;
    rflac_result result;

    assert(bs != NULL);
    assert(pResult != NULL);
    assert(bitCount > 0);
    assert(bitCount <= 32);

    result = rflac_bs_read_uint32(bs, bitCount, &x);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    /* Do not attempt to shift by 32 as it's undefined. */
    if (bitCount < 32) {
        rflac_uint32 signbit;
        signbit = ((x >> (bitCount-1)) & 0x01);
        x |= (~signbit + 1) << bitCount;
    }

    *pResult = (rflac_int32)x;
    return RFLAC_SUCCESS;
}

static rflac_result drflac_bs_read_uint64(rflac_bs* bs, unsigned int bitCount, rflac_uint64* pResultOut)
{
    rflac_uint32 xHi;
    rflac_uint32 xLo;
    rflac_result result;

    assert(bitCount <= 64);
    assert(bitCount >  32);

    result = rflac_bs_read_uint32(bs, bitCount - 32, &xHi);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    result = rflac_bs_read_uint32(bs, 32, &xLo);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    *pResultOut = (((rflac_uint64)xHi) << 32) | ((rflac_uint64)xLo);
    return RFLAC_SUCCESS;
}

static rflac_result rflac_bs_read_uint16(rflac_bs* bs, unsigned int bitCount, rflac_uint16* pResult)
{
    rflac_uint32 x;
    rflac_result result;

    assert(bs != NULL);
    assert(pResult != NULL);
    assert(bitCount > 0);
    assert(bitCount <= 16);

    result = rflac_bs_read_uint32(bs, bitCount, &x);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    *pResult = (rflac_uint16)x;
    return RFLAC_SUCCESS;
}

static rflac_result rflac_bs_read_uint8(rflac_bs* bs, unsigned int bitCount, rflac_uint8* pResult)
{
    rflac_uint32 x;
    rflac_result result;

    assert(bs != NULL);
    assert(pResult != NULL);
    assert(bitCount > 0);
    assert(bitCount <= 8);

    result = rflac_bs_read_uint32(bs, bitCount, &x);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    *pResult = (rflac_uint8)x;
    return RFLAC_SUCCESS;
}

static rflac_result rflac_bs_read_int8(rflac_bs* bs, unsigned int bitCount, rflac_int8* pResult)
{
    rflac_int32 x;
    rflac_result result;

    assert(bs != NULL);
    assert(pResult != NULL);
    assert(bitCount > 0);
    assert(bitCount <= 8);

    result = rflac_bs_read_int32(bs, bitCount, &x);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    *pResult = (rflac_int8)x;
    return RFLAC_SUCCESS;
}

static rflac_result rflac_bs_seek_bits(rflac_bs* bs, size_t bitsToSeek)
{
    if (bitsToSeek <= RFLAC_CACHE_L1_BITS_REMAINING(bs)) {
        bs->consumedBits += (rflac_uint32)bitsToSeek;
        bs->cache <<= bitsToSeek;
        return RFLAC_SUCCESS;
    } else {
        /* It straddles the cached data. This function isn't called too frequently so I'm favouring simplicity here. */
        bitsToSeek       -= RFLAC_CACHE_L1_BITS_REMAINING(bs);
        bs->consumedBits += RFLAC_CACHE_L1_BITS_REMAINING(bs);
        bs->cache         = 0;

        while (bitsToSeek >= RFLAC_CACHE_L1_SIZE_BITS(bs)) {
            rflac_uint64 bin;
            rflac_result result;

            result = drflac_bs_read_uint64(bs, RFLAC_CACHE_L1_SIZE_BITS(bs), &bin);
            if (result != RFLAC_SUCCESS) {
                return result;
            }

            bitsToSeek -= RFLAC_CACHE_L1_SIZE_BITS(bs);
        }

        /* Whole leftover bytes. */
        while (bitsToSeek >= 8) {
            rflac_uint8 bin;
            rflac_result result;

            result = rflac_bs_read_uint8(bs, 8, &bin);
            if (result != RFLAC_SUCCESS) {
                return result;
            }

            bitsToSeek -= 8;
        }

        /* Leftover bits. */
        if (bitsToSeek > 0) {
            rflac_uint8 bin;
            rflac_result result;

            result = rflac_bs_read_uint8(bs, (rflac_uint32)bitsToSeek, &bin);
            if (result != RFLAC_SUCCESS) {
                return result;
            }

            bitsToSeek = 0; /* <-- Necessary for the assert below. */
        }

        assert(bitsToSeek == 0);
        return RFLAC_SUCCESS;
    }
}

static rflac_result rflac_bs_seek_to_next_byte(rflac_bs* bs)
{
    assert(bs != NULL);

    return rflac_bs_seek_bits(bs, RFLAC_CACHE_L1_BITS_REMAINING(bs) & 7);
}

static rflac_result rflac_bs_read_unary(rflac_bs* bs, rflac_uint32* pValue)
{
    rflac_uint32 zeroCounter = 0;
    rflac_uint32 setBitOffsetPlus1;
    rflac_result result;

    while (bs->cache == 0) {
        zeroCounter += (rflac_uint32)RFLAC_CACHE_L1_BITS_REMAINING(bs);
        
        result = rflac_bs_reload_cache(bs);
        if (result != RFLAC_SUCCESS) {
            return result;
        }
    }

    if (bs->cache == 1) {
        /* Not catching this would lead to undefined behaviour: a shift of a 32-bit number by 32 or more is undefined */
        *pValue = zeroCounter + (rflac_uint32)RFLAC_CACHE_L1_BITS_REMAINING(bs) - 1;

        result = rflac_bs_reload_cache(bs);
        if (result != RFLAC_SUCCESS) {
            return result;
        }

        return RFLAC_SUCCESS;
    }

    setBitOffsetPlus1 = rflac_clz_64(bs->cache);
    setBitOffsetPlus1 += 1;

    if (setBitOffsetPlus1 > RFLAC_CACHE_L1_BITS_REMAINING(bs)) {
        /* This happens when we get to end of stream */
        return RFLAC_NOT_ENOUGH_DATA;
    }

    bs->consumedBits += setBitOffsetPlus1;
    bs->cache <<= setBitOffsetPlus1;

    *pValue = zeroCounter + setBitOffsetPlus1 - 1;
    return RFLAC_SUCCESS;
}



typedef enum
{
    RFLAC_METADATA_BLOCK_TYPE_STREAMINFO     = 0,
    RFLAC_METADATA_BLOCK_TYPE_PADDING        = 1,
    RFLAC_METADATA_BLOCK_TYPE_APPLICATION    = 2,
    RFLAC_METADATA_BLOCK_TYPE_SEEKTABLE      = 3,
    RFLAC_METADATA_BLOCK_TYPE_VORBIS_COMMENT = 4,
    RFLAC_METADATA_BLOCK_TYPE_CUESHEET       = 5,
    RFLAC_METADATA_BLOCK_TYPE_PICTURE        = 6
} rflac_metadata_block_type;

typedef struct
{
    rflac_bool8 last;
    rflac_uint8 type;
    size_t      size;
    const void* data;
} rflac_metadata_block;

static rflac_result rflac_read_metadata_block(const void* pData, size_t dataSize, size_t* pBytesConsumed, rflac_metadata_block* pMetadata)
{
    size_t totalBytesConsumed = 0;
    const unsigned char* pData8 = (const unsigned char*)pData;

    assert(pData8 != NULL);

    /*
    Section 9.1

        Each metadata block starts with a 4 byte header. The first bit in
        this header flags whether a metadata block is the last one, it is a 0
        when other metadata blocks follow, otherwise it is a 1.  The 7
        remaining bits of the first header byte contain the type of the
        metadata block as an unsigned number between 0 and 126 according to
        the following table.  A value of 127 (i.e. 0b1111111) is invalid.
        The three bytes that follow code for the size of the metadata block
        in bytes excluding the 4 header bytes as an unsigned number coded
        big-endian.
    */
    if (dataSize < 4) {
        return RFLAC_NOT_ENOUGH_DATA;
    }

    pMetadata->last = (pData8[0] & 0x80) != 0;
    pMetadata->type = (pData8[0] & 0x7F);
    pMetadata->size = (pData8[1] << 16) | (pData8[2] << 8) | (pData8[3] << 0);

    pData8             += 4;
    totalBytesConsumed += 4;

    /*
    Section 9.1

        A value of 127 (i.e. 0b1111111) is invalid.
    */
    if (pMetadata->type == 127) {
        return RFLAC_INVALID_FILE;
    }

    /* The data should be sitting on the data, but make sure there's enough data. */
    if ((dataSize - totalBytesConsumed) < pMetadata->size) {
        return RFLAC_NOT_ENOUGH_DATA;
    }

    pMetadata->data = (const void*)pData8;

    pData8             += pMetadata->size;
    totalBytesConsumed += pMetadata->size;


    /* Getting here means we successfully read the metadata. */
    *pBytesConsumed = totalBytesConsumed;

    return RFLAC_SUCCESS;
}


/*
9.2.  Streaminfo
*/
#define RFLAC_METADATA_BLOCK_STREAMINFO_SIZE    34

typedef struct
{
    rflac_uint16 minBlockSize;
    rflac_uint16 maxBlockSize;
    rflac_uint32 minFrameSizeInBytes;
    rflac_uint32 maxFrameSizeInBytes;
    rflac_uint32 sampleRate;
    rflac_uint8  channels;
    rflac_uint8  bitsPerSample;
    rflac_uint64 totalPCMFrameCount;
    rflac_uint8  md5[16];
} rflac_metadata_block_streaminfo;

static rflac_result rflac_read_metadata_block_streaminfo(rflac_metadata_block* pMetadata, rflac_metadata_block_streaminfo* pStreaminfo)
{
    const unsigned char* pData8 = (const unsigned char*)pMetadata->data;

    assert(pMetadata   != NULL);
    assert(pStreaminfo != NULL);

    if (pMetadata->size < RFLAC_METADATA_BLOCK_STREAMINFO_SIZE) {
        return RFLAC_INVALID_FILE;  /* The STREAMINFO block must be at least this size. If not, it's an invalid file. RFLAC_NOT_ENOUGH_DATA will have been returned at an earlier stage if relevant. */
    }

    pStreaminfo->minBlockSize        =   (pData8[ 0] <<  8) | (pData8[ 1] << 0);
    pStreaminfo->maxBlockSize        =   (pData8[ 2] <<  8) | (pData8[ 3] << 0);
    pStreaminfo->minFrameSizeInBytes =   (pData8[ 4] << 16) | (pData8[ 5] << 8) | (pData8[ 6] << 0);
    pStreaminfo->maxFrameSizeInBytes =   (pData8[ 7] << 16) | (pData8[ 8] << 8) | (pData8[ 9] << 0);
    pStreaminfo->sampleRate          =  ((pData8[10] << 16) | (pData8[11] << 8) | (pData8[12] << 0)) >> 4;
    pStreaminfo->channels            =  ((pData8[12] & 0x0E) >> 1) + 1;                                 /* +1 because it's stored as minus 1. */
    pStreaminfo->bitsPerSample       = (((pData8[12] & 0x01) << 4) | ((pData8[13] & 0xF0) >> 4)) + 1;   /* +1 because it's stored as minus 1. */
    pStreaminfo->totalPCMFrameCount  = (((rflac_uint64)pData8[13] & 0x0F) << 32) | ((pData8[14] << 24) | (pData8[15] << 16) | (pData8[16] << 8) | (pData8[17] << 0));

    return RFLAC_SUCCESS;
}



rflac_result rflac_init(rflac* pFlac, const void* pData, size_t dataSize, size_t* pBytesConsumed)
{
    size_t totalBytesConsumed = 0;
    const unsigned char* pData8 = (const unsigned char*)pData;

    if (pFlac == NULL) {
        return RFLAC_INVALID_ARGS;
    }

    memset(pFlac, 0, sizeof(*pFlac));

    if (pBytesConsumed == NULL) {
        return RFLAC_INVALID_ARGS;  /* You must know how many bytes were consumed for correct usage of this decoder. */
    }

    *pBytesConsumed = 0;

    if (pData == NULL) {
        return RFLAC_INVALID_ARGS;
    }


    /*
    Section 7.

        A FLAC bitstream consists of the fLaC (i.e. 0x664C6143) marker at the beginning of the stream
    */
    if ((dataSize - totalBytesConsumed) < 4) {
        return RFLAC_NOT_ENOUGH_DATA;
    }

    if (pData8[0] != 'f' && pData8[1] != 'L' && pData8[2] != 'a' && pData8[3] != 'C') {
        return RFLAC_INVALID_FILE;
    }

    pData8             += 4;
    totalBytesConsumed += 4;
    


    /*
    Section 7. (Cont. from above)

        followed by a mandatory metadata block (called the STREAMINFO block), any number of other metadata blocks,
        then the audio frames.
    */
    {
        rflac_result result;
        rflac_metadata_block metadata;
        rflac_metadata_block_streaminfo streaminfo;
        size_t bytesConsumed;

        /* STREAMINFO */
        result = rflac_read_metadata_block(pData8, dataSize - totalBytesConsumed, &bytesConsumed, &metadata);
        if (result != RFLAC_SUCCESS) {
            return result;
        }

        pData8             += bytesConsumed;
        totalBytesConsumed += bytesConsumed;

        if (metadata.type != RFLAC_METADATA_BLOCK_TYPE_STREAMINFO) {
            return RFLAC_INVALID_FILE;
        }

        /* Parse the STREAMINFO block so we can get some basic information and do some validation. */
        result = rflac_read_metadata_block_streaminfo(&metadata, &streaminfo);
        if (result != RFLAC_SUCCESS) {
            return RFLAC_INVALID_FILE;
        }

        /*
        Section 9.2

            FLAC specifies a minimum block size of 16 and a maximum block size of
            65535, meaning the bit patterns corresponding to the numbers 0-15 in
            the minimum block size and maximum block size fields are invalid.
        */
        if (streaminfo.minBlockSize < RFLAC_MIN_BLOCK_SIZE_IN_SAMPLES) {
            return RFLAC_INVALID_FILE;
        }

        if (streaminfo.channels < RFLAC_MIN_CHANNELS || streaminfo.channels > RFLAC_MAX_CHANNELS) {
            return RFLAC_INVALID_FILE;
        }

        if (streaminfo.sampleRate < RFLAC_MIN_SAMPLE_RATE || streaminfo.channels > RFLAC_MAX_SAMPLE_RATE) {
            return RFLAC_INVALID_FILE;
        }

        if (streaminfo.bitsPerSample < RFLAC_MIN_BITS_PER_SAMPLE || streaminfo.bitsPerSample > RFLAC_MAX_BITS_PER_SAMPLE) {
            return RFLAC_INVALID_FILE;
        }

        pFlac->bitsPerSample      = streaminfo.bitsPerSample;
        pFlac->sampleRate         = streaminfo.sampleRate;
        pFlac->channels           = streaminfo.channels;
        pFlac->totalPCMFrameCount = streaminfo.totalPCMFrameCount;
        pFlac->minBlockSize       = streaminfo.minBlockSize;
        pFlac->maxBlockSize       = streaminfo.maxBlockSize;

        /* Remaining metadata blocks. */
        for (;;) {
            result = rflac_read_metadata_block(pData8, dataSize - totalBytesConsumed, &bytesConsumed, &metadata);
            if (result != RFLAC_SUCCESS) {
                return result;
            }

            pData8             += bytesConsumed;
            totalBytesConsumed += bytesConsumed;

            /*
            Section 9.2

                There MUST be no more than one streaminfo
                metadata block per FLAC stream.
            */
            if (metadata.type == RFLAC_METADATA_BLOCK_TYPE_STREAMINFO) {
                return RFLAC_INVALID_FILE;
            }

            if (metadata.last == 1) {
                break;
            }
        }
    }
    

    /* Getting here means we're done with initialization. The next part should be audio data. */
    *pBytesConsumed = totalBytesConsumed;

    return RFLAC_SUCCESS;
}


typedef enum
{
    RFLAC_STEREO_DECORRELATION_MODE_INDEPENDANT,
    RFLAC_STEREO_DECORRELATION_MODE_LEFT_SIDE,
    RFLAC_STEREO_DECORRELATION_MODE_SIDE_RIGHT,
    RFLAC_STEREO_DECORRELATION_MODE_MID_SIDE
} rflac_stereo_decorrelation_mode;

typedef struct
{
    rflac_uint16 syncCode;
    rflac_uint8 blockingStrategy;
    rflac_uint64 pcmFrameIndex; /* The index of the first PCM frame in the stream this FLAC frame encodes. */
    rflac_uint16 pcmFrameCount;
    rflac_uint32 sampleRate;
    rflac_uint8 channels;
    rflac_stereo_decorrelation_mode stereoDecorrelationMode;
    rflac_uint8 bitsPerSample;
    rflac_uint32 crc8;
} rflac_frame_header;

static rflac_result rflac_decode_frame_header(rflac* pFlac, const void* pData, size_t dataSize, size_t* pBytesConsumed, rflac_frame_header* pFrameHeader)
{
    size_t totalBytesConsumed = 0;
    const unsigned char* pData8 = (const unsigned char*)pData;
    rflac_uint8 blocksizeCode;
    rflac_uint8 sampleRateCode;
    rflac_uint8 channelCode;
    rflac_uint8 bitDepthCode;
    rflac_uint32 codedNumber;   /* Either a PCM frame number, or a FLAC frame number, depending on the blocking strategy. */
    rflac_uint32 codedNumberByteCount;

    assert(pFlac          != NULL);
    assert(pData          != NULL);
    assert(pBytesConsumed != NULL);
    assert(pFrameHeader   != NULL);

    *pBytesConsumed = 0;


    /*
    Section 10.1

        Each frame MUST start on a byte boundary and starts with the 15-bit
        frame sync code 0b111111111111100.  Following the sync code is the
        blocking strategy bit, which MUST NOT change during the audio stream.
    */
    if ((dataSize - totalBytesConsumed) < 4) {
        return RFLAC_NOT_ENOUGH_DATA;
    }

    pFrameHeader->syncCode         = ((pData8[0] << 8) | (pData8[1] << 0)) & 0xFFFE;
    pFrameHeader->blockingStrategy = pData8[1] & 0x01;

    if (pFrameHeader->syncCode != 0xFFF8) {
        return RFLAC_INVALID_FILE;
    }


    /*
    Section 10.1.1

        Following the frame sync code and blocksize strategy bit are 4 bits
        referred to as the blocksize bits.
    */
    blocksizeCode = (pData8[2] & 0xF0) >> 4;

    if (blocksizeCode == 0) {
        return RFLAC_INVALID_FILE;  /* Reserved. */
    }

    if (blocksizeCode == 1) {
        pFrameHeader->pcmFrameCount = 192;
    } else if (blocksizeCode >= 2 && blocksizeCode <= 5) {
        pFrameHeader->pcmFrameCount = 144 << blocksizeCode;
    } else if (blocksizeCode == 6 || blocksizeCode == 7) {
        // Will be read later.
    } else if (blocksizeCode >= 8 && blocksizeCode <= 15) {
        pFrameHeader->pcmFrameCount = 1 << blocksizeCode;
    } else {
        return RFLAC_INVALID_FILE;  /* Should never hit this. */
    }


    /*
    Section 10.1.2

        The next 4 bits, referred to as the sample rate bits, contain the
        sample rate according to the following table.
    */
    sampleRateCode = (pData8[2] & 0x0F);

    if (sampleRateCode == 0) {
        pFrameHeader->sampleRate = pFlac->sampleRate;
    } else if (sampleRateCode >= 1 && sampleRateCode <= 11) {
        rflac_uint32 sampleRateLookup[] = {
            0,  /* Unused. */
            88200,
            176400,
            192000,
            8000,
            16000,
            22050,
            24000,
            32000,
            44100,
            48000,
            96000
        };

        pFrameHeader->sampleRate = sampleRateLookup[sampleRateCode];
    } else if (sampleRateCode >= 12 && sampleRateCode <= 14) {
        // Will be read later.
    } else {
        return RFLAC_INVALID_FILE;
    }


    /*
    Section 10.1.3

        The next 4 bits (the first 4 bits of the fourth byte of each frame),
        referred to as the channels bits, code for both the number of
        channels as well as any stereo decorrelation used
    */
    channelCode = (pData8[3] & 0xF0) >> 4;

    pFrameHeader->stereoDecorrelationMode = RFLAC_STEREO_DECORRELATION_MODE_INDEPENDANT;
    if (channelCode >= 0 && channelCode <= 7) {
        pFrameHeader->channels = channelCode + 1;
    } else if (channelCode == 8) {
        pFrameHeader->channels = 2;
        pFrameHeader->stereoDecorrelationMode = RFLAC_STEREO_DECORRELATION_MODE_LEFT_SIDE;
    } else if (channelCode == 9) {
        pFrameHeader->channels = 2;
        pFrameHeader->stereoDecorrelationMode = RFLAC_STEREO_DECORRELATION_MODE_SIDE_RIGHT;
    } else if (channelCode == 10) {
        pFrameHeader->channels = 2;
        pFrameHeader->stereoDecorrelationMode = RFLAC_STEREO_DECORRELATION_MODE_MID_SIDE;
    } else {
        return RFLAC_INVALID_FILE;
    }


    /*
    Section 10.1.4

        The next 3 bits code for the bit depth of the samples in the subframe
    */
    bitDepthCode = (pData8[3] & 0x0E) >> 1;

    if (bitDepthCode == 0) {
        pFrameHeader->bitsPerSample = pFlac->bitsPerSample;
    } else if (bitDepthCode == 1) {
        pFrameHeader->bitsPerSample = 8;
    } else if (bitDepthCode == 2) {
        pFrameHeader->bitsPerSample = 12;
    } else if (bitDepthCode == 3) {
        return RFLAC_INVALID_FILE;
    } else if (bitDepthCode == 4) {
        pFrameHeader->bitsPerSample = 16;
    } else if (bitDepthCode == 5) {
        pFrameHeader->bitsPerSample = 20;
    } else if (bitDepthCode == 6) {
        pFrameHeader->bitsPerSample = 24;
    } else if (bitDepthCode == 7) {
        pFrameHeader->bitsPerSample = 32;
    }


    /*
    Section 10.1.4

        The next bit is reserved and MUST be zero.
    */
    if ((pData8[3] & 0x01) != 0) {
        return RFLAC_INVALID_FILE;
    }

    pData8             += 4;
    totalBytesConsumed += 4;

    
    /*
    Section 10.1.5

        Following the reserved bit (starting at the fifth byte of the frame)
        is either a sample or a frame number, which will be referred to as
        the coded number.  When dealing with variable blocksize streams, the
        sample number of the first sample in the frame is encoded.  When the
        file contains a fixed blocksize stream, the frame number is encoded.
        The coded number is stored in a variable length code like UTF-8, but
        extended to a maximum of 36 bits unencoded, 7 byte encoded.
    */
    if ((dataSize - totalBytesConsumed) < 1) {
        return RFLAC_NOT_ENOUGH_DATA;
    }

    /*  */ if ((pData8[0] & 0x80) == 0) {
        codedNumberByteCount = 1;
        codedNumber = pData8[0] & 0x7F;
    } else if ((pData8[0] & 0xE0) == 0xC0) {
        codedNumberByteCount = 2;
        codedNumber = pData8[0] & 0x1F;
    } else if ((pData8[0] & 0xF0) == 0xE0) {
        codedNumberByteCount = 3;
        codedNumber = pData8[0] & 0x0F;
    } else if ((pData8[0] & 0xF8) == 0xF0) {
        codedNumberByteCount = 4;
        codedNumber = pData8[0] & 0x07;
    } else if ((pData8[0] & 0xFC) == 0xF8) {
        codedNumberByteCount = 5;
        codedNumber = pData8[0] & 0x03;
    } else if ((pData8[0] & 0xFE) == 0xFC) {
        codedNumberByteCount = 6;
        codedNumber = pData8[0] & 0x01;
    } else if ((pData8[0] & 0xFF) == 0xFE) {
        codedNumberByteCount = 7;
        codedNumber = 0;
    } else {
        return RFLAC_INVALID_FILE;
    }

    if ((dataSize - totalBytesConsumed) < codedNumberByteCount - 1) {
        return RFLAC_NOT_ENOUGH_DATA;
    }

    /* Construct the rest of the UTF-8 encoded number. */
    {
        rflac_uint32 iByte;
        for (iByte = 1; iByte < codedNumberByteCount; iByte += 1) {
            codedNumber = (codedNumber << 6) | (pData8[iByte] & 0x3F);
        }
    }

    if (pFrameHeader->blockingStrategy == 0) {
        pFrameHeader->pcmFrameIndex = codedNumber * pFlac->maxBlockSize;
    } else {
        pFrameHeader->pcmFrameIndex = codedNumber;
    }


    pData8             += codedNumberByteCount;
    totalBytesConsumed += codedNumberByteCount;


    /*
    Section 10.1.6.

        If the blocksize bits defined earlier in this section were 0b0110 or
        0b0111 (uncommon blocksize minus 1 stored), this follows the coded
        number as either an 8-bit or a 16-bit unsigned number coded big-
        endian.
    */
    if (blocksizeCode == 6) {
        if ((dataSize - totalBytesConsumed) < 1) {
            return RFLAC_NOT_ENOUGH_DATA;
        }

        pFrameHeader->pcmFrameCount = pData8[0] + 1;

        pData8             += 1;
        totalBytesConsumed += 1;
    } else if (blocksizeCode == 7) {
        if ((dataSize - totalBytesConsumed) < 2) {
            return RFLAC_NOT_ENOUGH_DATA;
        }

        pFrameHeader->pcmFrameCount = (rflac_uint16)((pData8[0] << 8) | (pData8[1] << 0)) + 1;

        pData8             += 2;
        totalBytesConsumed += 2;
    }

    


    /*
    Section 10.1.7.

        Following the uncommon blocksize (or the coded number if no uncommon
        blocksize is stored) is the sample rate, if the sample rate bits were
        0b1100, 0b1101 or 0b1110 (uncommon sample rate stored), as either an
        8-bit or a 16-bit unsigned number coded big-endian.
    */
    if (sampleRateCode == 12) {
        if ((dataSize - totalBytesConsumed) < 1) {
            return RFLAC_NOT_ENOUGH_DATA;
        }

        pFrameHeader->sampleRate = pData8[0];

        pData8             += 1;
        totalBytesConsumed += 1;
    } else if (sampleRateCode == 13 || sampleRateCode == 14) {
        if ((dataSize - totalBytesConsumed) < 1) {
            return RFLAC_NOT_ENOUGH_DATA;
        }

        pFrameHeader->sampleRate = (rflac_uint32)((pData8[0] << 8) | (pData8[1] << 0));
        if (sampleRateCode == 14) {
            pFrameHeader->sampleRate *= 10;
        }

        pData8             += 2;
        totalBytesConsumed += 2;
    }



    /*
    Section 10.1.8.

        after either the frame/sample number, an uncommon blocksize
        or an uncommon sample rate, depending on whether the latter two are
        stored, is an 8-bit CRC.
    */
    if ((dataSize - totalBytesConsumed) < 1) {
        return RFLAC_NOT_ENOUGH_DATA;
    }

    pFrameHeader->crc8 = pData8[0];

    pData8             += 1;
    totalBytesConsumed += 1;



    /* Getting here means the frame header has been decoded. */
    *pBytesConsumed = totalBytesConsumed;

    return RFLAC_SUCCESS;
}


typedef enum
{
    RFLAC_SUBFRAME_TYPE_CONSTANT,
    RFLAC_SUBFRAME_TYPE_VERBATIM,
    RFLAC_SUBFRAME_TYPE_FIXED,
    RFLAC_SUBFRAME_TYPE_LPC
} rflac_subframe_type;

typedef enum
{
    RFLAC_RESIDUAL_CODING_METHOD_PARTITIONED_RICE_4 = 0x00,
    RFLAC_RESIDUAL_CODING_METHOD_PARTITIONED_RICE_5 = 0x01,
} rflac_residual_coding_method;

typedef struct
{
    rflac_subframe_type type;
    rflac_uint32 predictorOrder;
    rflac_uint32 wastedBits;
} rflac_subframe_header;

static rflac_result rflac_decode_subframe_header(rflac* pFlac, rflac_bs* pBS, rflac_subframe_header* pSubframeHeader)
{
    rflac_result result;
    rflac_uint8 headerByte;
    rflac_uint8 subframeTypeCode;
    

    assert(pFlac           != NULL);
    assert(pSubframeHeader != NULL);

    /*
    Section 10.2.1

        The first bit of the header is always 0
    */
    result = rflac_bs_read_uint8(pBS, 8, &headerByte);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    if ((headerByte & 0x80) != 0) {
        return RFLAC_INVALID_FILE;
    }

    subframeTypeCode = (headerByte & 0x7E) >> 1;
    if (subframeTypeCode == 0) {
        pSubframeHeader->type = RFLAC_SUBFRAME_TYPE_CONSTANT;
    } else if (subframeTypeCode == 1) {
        pSubframeHeader->type = RFLAC_SUBFRAME_TYPE_VERBATIM;
    } else if (subframeTypeCode >= 2 && subframeTypeCode <= 7) {
        return RFLAC_INVALID_FILE;
    } else if (subframeTypeCode >= 8 && subframeTypeCode <= 12) {
        pSubframeHeader->type = RFLAC_SUBFRAME_TYPE_FIXED;
        pSubframeHeader->predictorOrder = subframeTypeCode - 8;
    } else if (subframeTypeCode >= 13 && subframeTypeCode <= 31) {
        return RFLAC_INVALID_FILE;
    } else if (subframeTypeCode >= 32 && subframeTypeCode <= 63) {
        pSubframeHeader->type = RFLAC_SUBFRAME_TYPE_LPC;
        pSubframeHeader->predictorOrder = subframeTypeCode - 31;
    } else {
        return RFLAC_INVALID_FILE;
    }


    /*
    Section 10.2.1

        Following the subframe type bits is a bit that flags whether the
        subframe has any wasted bits.  If it is 0, the subframe doesn't have
        any wasted bits and the subframe header is complete.  If it is 1, the
        subframe does have wasted bits and the number of wasted bits follows
        unary coded.
    */
    pSubframeHeader->wastedBits = 0;
    if ((headerByte & 0x01) != 0) {
        result = rflac_bs_read_unary(pBS, &pSubframeHeader->wastedBits);
        if (result != RFLAC_SUCCESS) {
            return result;
        }

        pSubframeHeader->wastedBits += 1;   /* Section 10.2.2: If this is the case, the number of wasted bits-per-sample (k) minus 1 follows the flag */
    }

    return RFLAC_SUCCESS;
}

static rflac_int32 rflac_calculate_prediction(rflac_uint32 predictionShift, rflac_uint32 predictorOrder, rflac_int32* pPredictorCoefficients, rflac_int32* pCurrentSample)
{
    rflac_int32 iOrder;
    rflac_int64 prediction = 0;

    for (iOrder = 0; iOrder < (rflac_int32)predictorOrder; iOrder += 1) {
        prediction += pPredictorCoefficients[iOrder] * (rflac_int64)pCurrentSample[-iOrder - 1];
    }

    return (rflac_int32)(prediction >> predictionShift);
}

static rflac_result rflac_decode_residual_and_apply_prediction(rflac_bs* pBS, rflac_uint32 pcmFrameCount, rflac_uint32 predictionShift, rflac_uint32 predictorOrder, rflac_int32* pPredictorCoefficients, rflac_int32* pSamples)
{
    rflac_result result;
    rflac_uint32 iSample;
    rflac_uint8 residualCodingMethod;
    rflac_uint8 partitionOrder;
    rflac_uint32 iPartition;

    /*
    Section 10.2.7

        The first two bits in a coded residual indicate which coding method
        is used.
    */
    result = rflac_bs_read_uint8(pBS, 2, &residualCodingMethod);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    if (residualCodingMethod != RFLAC_RESIDUAL_CODING_METHOD_PARTITIONED_RICE_4 && residualCodingMethod != RFLAC_RESIDUAL_CODING_METHOD_PARTITIONED_RICE_5) {
        return RFLAC_INVALID_FILE;
    }


    /*
    Section 10.2.7

        The 4 bits that directly follow the coding method bits form the partition
        order, which is an unsigned number.
    */
    result = rflac_bs_read_uint8(pBS, 4, &partitionOrder);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    iSample = predictorOrder;    /* <-- We've already got our warmup samples decoded. */

    for (iPartition = 0; iPartition < (1UL << partitionOrder); iPartition += 1) {
        rflac_uint32 iSampleEnd;
        rflac_uint8 riceParameter;
        rflac_bool8 isUnencoded = RFLAC_FALSE;

        if (residualCodingMethod == RFLAC_RESIDUAL_CODING_METHOD_PARTITIONED_RICE_4) {
            result = rflac_bs_read_uint8(pBS, 4, &riceParameter);
            if (result != RFLAC_SUCCESS) {
                return result;
            }

            if (riceParameter == 15) {
                isUnencoded = RFLAC_TRUE;
            }
        } else {
            result = rflac_bs_read_uint8(pBS, 5, &riceParameter);
            if (result != RFLAC_SUCCESS) {
                return result;
            }

            if (riceParameter == 31) {
                isUnencoded = RFLAC_TRUE;
            }
        }

        iSampleEnd = (iPartition + 1) * (pcmFrameCount >> partitionOrder);

        if (isUnencoded) {
            /*
            Section 10.2.7

                In case an escape code was used, the partition does not contain a
                variable-length Rice coded residual, but a fixed-length unencoded
                residual.  Directly following the escape code are 5 bits containing
                the number of bits with which each residual sample is stored, as an
                unsigned number.
            */
            rflac_uint8 bitsPerResidualSample;

            result = rflac_bs_read_uint8(pBS, 5, &bitsPerResidualSample);
            if (result != RFLAC_SUCCESS) {
                return result;
            }

            while (iSample < iSampleEnd) {
                rflac_int32 residual;
                rflac_int32 prediction;

                /*
                Section 10.2.7

                    Note that it is possible that the number of bits is 0, which means
                    all residual samples in that partition have a value of 0, and no bits
                    code for the partition itself.
                */
                if (bitsPerResidualSample > 0) {
                    result = rflac_bs_read_int32(pBS, bitsPerResidualSample, &residual);
                    if (result != RFLAC_SUCCESS) {
                        return result;
                    }
                } else {
                    residual = 0;
                }

                /* Prediction. */
                prediction = rflac_calculate_prediction(predictionShift, predictorOrder, pPredictorCoefficients, &pSamples[iSample]);

                /* Reconstruction. */
                pSamples[iSample] = residual + prediction;

                iSample += 1;
            }
        } else {
            /*
            This is where the real Rice decoding happens. The spec is not very clear about how to do this, so
            here's a clearer and more explicit explanation:

                Each code word is made up of a unary number followed by a binary number. The unary number can
                be decoded by counting the number of leading zero bits before the next set bit. That is, keep
                counting zero bits until a set bit is encounted, and skip past the set bit. The leading zeros
                and the set bit are what make up the unary coded number. The value of the number is equal to
                the number of zero bits. The binary number follows. The number of bits making up this number
                is equal to the rice parameter that was retrieved at the start of the current Rice partition.

                To complete decoding the Rice encoded code word, shift the unary number to the left by the
                rice parameter, then bitwise OR the binary number. If at this stage the code word is even, it
                means the number is positive and needs only be divided by 2. Otherwise it means the number is
                negative and the number needs to have 1 added to it, then divided by -2.

            For the negative number conversion (the last part in the explanation above), you can just shift
            right by 1 and flip the bits to make it a usable two's compliment negative number thereby avoiding
            the overhead of a division.
            */
            while (iSample < iSampleEnd) {
                rflac_uint32 unary;
                rflac_uint32 binary;
                rflac_uint32 residual;
                rflac_int32  prediction = 0;

                /* Residual. */
                result = rflac_bs_read_unary(pBS, &unary);
                if (result != RFLAC_SUCCESS) {
                    return result;
                }

                if (riceParameter > 0) {
                    result = rflac_bs_read_uint32(pBS, riceParameter, &binary);
                    if (result != RFLAC_SUCCESS) {
                        return result;
                    }
                } else {
                    binary = 0;
                }

                residual = (unary << riceParameter) | binary;
                if ((residual & 0x01) == 0) {
                    residual =  (residual >> 1);    /* Positive. Just divide by 2. */
                } else {
                    residual = ~(residual >> 1);    /* Negative. Divide by 2 and flip the bits to convert to two's compliment representation. */
                }

                /* Prediction. */
                prediction = rflac_calculate_prediction(predictionShift, predictorOrder, pPredictorCoefficients, &pSamples[iSample]);

                /* Reconstruction. */
                pSamples[iSample] = residual + prediction;

                iSample += 1;
            }
        }
    }

    return RFLAC_SUCCESS;
}

rflac_result rflac_decode_frame(rflac* pFlac, const void* pData, size_t dataSize, size_t* pBytesConsumed)
{
    size_t totalBytesConsumed = 0;
    const unsigned char* pData8 = (const unsigned char*)pData;
    size_t bytesConsumed;
    rflac_result result;
    rflac_frame_header frameHeader;
    rflac_subframe_header subframeHeaders[RFLAC_MAX_CHANNELS];
    rflac_uint32 iSubframe;
    rflac_uint32 iSample;
    rflac_uint16 crc16;
    rflac_bs bs;

    if (pBytesConsumed == NULL) {
        return RFLAC_INVALID_ARGS;  /* You must know how many bytes were consumed for correct usage of this decoder. */
    }

    *pBytesConsumed = 0;

    if (pFlac == NULL || pData == NULL) {
        return RFLAC_INVALID_ARGS;
    }

    result = rflac_decode_frame_header(pFlac, pData8, dataSize - totalBytesConsumed, &bytesConsumed, &frameHeader);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    pData8             += bytesConsumed;
    totalBytesConsumed += bytesConsumed;

    pFlac->frame.channels      = frameHeader.channels;
    pFlac->frame.sampleRate    = frameHeader.sampleRate;
    pFlac->frame.pcmFrameCount = frameHeader.pcmFrameCount;

    /*
    From here on out until the end of the frame, nothing can be considered byte aligned so we'll need to read
    from a bit stream instead. To help with this I'm using an abstraction just to make it a bit cleaner.
    */
    result = rflac_bs_init(pData8, dataSize - totalBytesConsumed, &bs);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    for (iSubframe = 0; iSubframe < frameHeader.channels; iSubframe += 1) {
        rflac_uint32 bitsToReadPerUnencodedSample;

        result = rflac_decode_subframe_header(pFlac, &bs, &subframeHeaders[iSubframe]);
        if (result != RFLAC_SUCCESS) {
            return result;
        }

        /*
        Section 10.2.3

            The bit depth of a subframe is equal to the bit depth as coded in
            the frame header (#bit-depth-bits), minus the number of wasted bits
            coded in the subframe header
        */
        bitsToReadPerUnencodedSample = frameHeader.bitsPerSample - subframeHeaders[iSubframe].wastedBits;

        /*
        Section 10.2.3

            In case a subframe is a side subframe (see the section on interchannel
            decorrelation (#interchannel-decorrelation)), the bit depth of that
            subframe is increased by 1 bit.
        */
        if (((frameHeader.stereoDecorrelationMode == RFLAC_STEREO_DECORRELATION_MODE_MID_SIDE || frameHeader.stereoDecorrelationMode == RFLAC_STEREO_DECORRELATION_MODE_LEFT_SIDE) && iSubframe == 1) ||
            ((frameHeader.stereoDecorrelationMode == RFLAC_STEREO_DECORRELATION_MODE_SIDE_RIGHT) && iSubframe == 0)) {
            bitsToReadPerUnencodedSample += 1;
        }

        switch (subframeHeaders[iSubframe].type)
        {
            case RFLAC_SUBFRAME_TYPE_CONSTANT:
            {
                rflac_int32 sample;
                result = rflac_bs_read_int32(&bs, bitsToReadPerUnencodedSample, &sample);
                if (result != RFLAC_SUCCESS) {
                    return result;
                }

                for (iSample = 0; iSample < frameHeader.pcmFrameCount; iSample += 1) {
                    pFlac->frame.pcm[iSubframe][iSample] = sample;
                }
            } break;

            case RFLAC_SUBFRAME_TYPE_VERBATIM:
            {
                for (iSample = 0; iSample < frameHeader.pcmFrameCount; iSample += 1) {
                    result = rflac_bs_read_int32(&bs, bitsToReadPerUnencodedSample, &pFlac->frame.pcm[iSubframe][iSample]);
                    if (result != RFLAC_SUCCESS) {
                        return result;
                    }
                }
            } break;

            case RFLAC_SUBFRAME_TYPE_FIXED:
            {
                rflac_int32 predictorCoefficients[5][4] =
                {
                    {0,  0, 0,  0},
                    {1,  0, 0,  0},
                    {2, -1, 0,  0},
                    {3, -3, 1,  0},
                    {4, -6, 4, -1}
                };

                /*
                Section 10.2.5

                    To be able to predict samples, warm-up samples are stored, as the
                    predictor needs previous samples in its prediction.  The number of
                    warm-up samples is equal to the predictor order.
                */
                for (iSample = 0; iSample < subframeHeaders[iSubframe].predictorOrder; iSample += 1) {
                    result = rflac_bs_read_int32(&bs, bitsToReadPerUnencodedSample, &pFlac->frame.pcm[iSubframe][iSample]);
                    if (result != RFLAC_SUCCESS) {
                        return result;
                    }
                }

                /* Residual comes after the warmup samples (the spec is not as clear as it could be about this). */
                result = rflac_decode_residual_and_apply_prediction(&bs, frameHeader.pcmFrameCount, 0, subframeHeaders[iSubframe].predictorOrder, predictorCoefficients[subframeHeaders[iSubframe].predictorOrder], pFlac->frame.pcm[iSubframe]);
                if (result != RFLAC_SUCCESS) {
                    return result;
                }
            } break;

            case RFLAC_SUBFRAME_TYPE_LPC:
            {
                rflac_int32  predictionShift;
                rflac_uint32 predictorCoefficientPrecision;
                rflac_int32  predictorCoefficients[32];
                rflac_uint32 iPredictorCoefficient;


                /* Warmup samples. */
                for (iSample = 0; iSample < subframeHeaders[iSubframe].predictorOrder; iSample += 1) {
                    result = rflac_bs_read_int32(&bs, bitsToReadPerUnencodedSample, &pFlac->frame.pcm[iSubframe][iSample]);
                    if (result != RFLAC_SUCCESS) {
                        return result;
                    }
                }


                /* Predictor precision. */
                result = rflac_bs_read_uint32(&bs, 4, &predictorCoefficientPrecision);
                if (result != RFLAC_SUCCESS) {
                    return result;
                }

                if (predictorCoefficientPrecision >= 15) {
                    return RFLAC_INVALID_FILE;
                }

                predictorCoefficientPrecision += 1;


                /* Prediction shift. */
                result = rflac_bs_read_int32(&bs, 5, &predictionShift);
                if (result != RFLAC_SUCCESS) {
                    return result;
                }

                if (predictionShift < 0) {
                    return RFLAC_INVALID_FILE;
                }


                /* Predictor coefficients. */
                for (iPredictorCoefficient = 0; iPredictorCoefficient < subframeHeaders[iSubframe].predictorOrder; iPredictorCoefficient += 1) {
                    result = rflac_bs_read_int32(&bs, predictorCoefficientPrecision, &predictorCoefficients[iPredictorCoefficient]);
                    if (result != RFLAC_SUCCESS) {
                        return result;
                    }
                }


                /* Residual. */
                result = rflac_decode_residual_and_apply_prediction(&bs, frameHeader.pcmFrameCount, predictionShift, subframeHeaders[iSubframe].predictorOrder, predictorCoefficients, pFlac->frame.pcm[iSubframe]);
                if (result != RFLAC_SUCCESS) {
                    return result;
                }
            } break;
            
            default:
            {
                return RFLAC_INVALID_FILE;
            }
        }
    }

    /*
    Here is where we need to do some post-processing of the audio data. If interchannel decorrelation is required
    we'll need to do that first. Then we need to shift each sample to the right so they're all normalized to 32-bit.
    */
    if (frameHeader.stereoDecorrelationMode == RFLAC_STEREO_DECORRELATION_MODE_INDEPENDANT) {
        for (iSubframe = 0; iSubframe < frameHeader.channels; iSubframe += 1) {
            rflac_uint32 shift = (32 - (frameHeader.bitsPerSample + subframeHeaders[iSubframe].wastedBits));

            for (iSample = 0; iSample < frameHeader.pcmFrameCount; iSample += 1) {
                pFlac->frame.pcm[iSubframe][iSample] <<= shift;
            }
        }
    } else {
        rflac_uint32 shift0 = (32 - (frameHeader.bitsPerSample + subframeHeaders[0].wastedBits));
        rflac_uint32 shift1 = (32 - (frameHeader.bitsPerSample + subframeHeaders[1].wastedBits));

        switch (frameHeader.stereoDecorrelationMode)
        {
            case RFLAC_STEREO_DECORRELATION_MODE_MID_SIDE:
            {
                for (iSample = 0; iSample < frameHeader.pcmFrameCount; iSample += 1) {
                    rflac_int32 mid  = pFlac->frame.pcm[0][iSample];
                    rflac_int32 side = pFlac->frame.pcm[1][iSample];

                    /*
                    Section 5.2

                        On decoding, all mid channel samples have to be shifted left by 1 bit.
                    */
                    mid = mid << 1;

                    /*
                    Section 5.2

                        Also, if a side channel sample is odd, 1 has to be added to
                        the corresponding mid channel sample after it has been shifted
                        left by one bit.
                    */
                    side = (side << 1) + (side & 0x01);

                    /*
                    Section 5.2

                        To reconstruct the left channel, the corresponding samples in
                        the mid and side subframes are added and the result shifted
                        right by 1 bit, while for the right channel the side channel
                        has to be subtracted from the mid channel and the result shifted
                        right by 1 bit.
                    */
                    pFlac->frame.pcm[0][iSample] = (mid + side) >> 1;
                    pFlac->frame.pcm[1][iSample] = (mid - side) >> 1;

                    /* Normalize to 32-bit. */
                    pFlac->frame.pcm[0][iSample] <<= shift0;
                    pFlac->frame.pcm[1][iSample] <<= shift1;
                }
            } break;

            case RFLAC_STEREO_DECORRELATION_MODE_LEFT_SIDE:
            {
                for (iSample = 0; iSample < frameHeader.pcmFrameCount; iSample += 1) {
                    rflac_int32 left = pFlac->frame.pcm[0][iSample];
                    rflac_int32 side = pFlac->frame.pcm[1][iSample];

                    /*
                    Section 5.2

                        To decode, the right subblock is restored by subtracting the samples
                        in the side subframe from the corresponding samples the left subframe.
                    */
                    pFlac->frame.pcm[1][iSample] = (left - side);

                    /* Normalize to 32-bit. */
                    pFlac->frame.pcm[0][iSample] <<= shift0;
                    pFlac->frame.pcm[1][iSample] <<= shift1;
                }
            } break;

            case RFLAC_STEREO_DECORRELATION_MODE_SIDE_RIGHT:
            {
                for (iSample = 0; iSample < frameHeader.pcmFrameCount; iSample += 1) {
                    rflac_int32 side  = pFlac->frame.pcm[0][iSample];
                    rflac_int32 right = pFlac->frame.pcm[1][iSample];

                    /*
                    Section 5.2

                        To decode, the left subblock is restored by adding the samples in the
                        side subframe to the corresponding samples in the right subframe.
                    */
                    pFlac->frame.pcm[0][iSample] = (side + right);

                    /* Normalize to 32-bit. */
                    pFlac->frame.pcm[0][iSample] <<= shift0;
                    pFlac->frame.pcm[1][iSample] <<= shift1;
                }
            } break;

            case RFLAC_STEREO_DECORRELATION_MODE_INDEPENDANT:   /* <-- To silence a warning. Will never hit this. */
            default:
            {
                return RFLAC_INVALID_FILE;  /* Should never hit this. */
            }
        }
    }



    /*
    Section 10.3

        Following the last subframe is the frame footer.  If the last
        subframe is not byte aligned (i.e. the bits required to store all
        subframes put together are not divisible by 8), zero bits are added
        until byte alignment is reached.
    */
    result = rflac_bs_seek_to_next_byte(&bs);
    if (result != RFLAC_SUCCESS) {
        return result;
    }

    /*
    Section 10.3

        Following this is a 16-bit CRC
    */
    result = rflac_bs_read_uint16(&bs, 16, &crc16);
    if (result != RFLAC_SUCCESS) {
        return result;
    }
    

    /* We're done with the bitstream. Make sure the buffer is advanced. */
    pData8             += rflac_bs_get_bytes_consumed(&bs);
    totalBytesConsumed += rflac_bs_get_bytes_consumed(&bs);


    /* Getting here means we're done with decoding the frame. */
    *pBytesConsumed = totalBytesConsumed;
    
    return RFLAC_SUCCESS;
}
