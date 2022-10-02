/*
A simple FLAC decoder written to test the FLAC specification listed here: https://datatracker.ietf.org/doc/draft-ietf-cellar-flac/

Additionally, this library is intended to act as an easy to read reference for myself and anybody
else who might find it useful. It's also being used as a place to experiment with some ideas that
could be integrated into dr_flac.

This uses a push style API where you supply the decoding functions with a buffer containing the
encoded FLAC data. The idea is that you decode FLAC frames one at a time which will contain a
number of PCM frames that you can use to do your required processing.

Call `rflac_init()` to initialize a decoder. This will return `RFLAC_NOT_ENOUGH_DATA` if you did
not supply enough data to initialize the decoder. In this case you need to call the function again
with more data. The number of bytes that were consumed will be returned via the `pBytesConsumed`
parameter. You must account for this when supplying more data when decoding. You are responsible
for allocating the `rflac` structure.

To decode a FLAC frame, call `rflac_decode_frame()`. The decoded PCM data, along with the channel
count and sample rate will be stored in the `frame` member in the `rflac` structure.

This library is not designed to be used in production environments. It was built mainly to assess
and test the FLAC spec linked above, but to also experiment with some ideas for a push style API
that could possibly be integrated with dr_flac.

Limitations:

    - No significant optimizations
    - Not fully tested
    - No CRC checks (if a CRC check fails results are undefined)
    - Only the native FLAC container is supported (no Ogg, Matroska or MP4)
    - The `rflac` structure is excessively big (do not allocate this on the stack!)
    - The API is not stable and will almost definitely change

Going forward a may make some updates to this library to get it production quality but that's still
undecided as of writing this. The library will probably be renamed as well.

For a production quality FLAC decoder, see dr_flac here: https://github.com/mackron/dr_libs. Note
that dr_flac does *not* support a push style API, but instead uses a pulling style API (this
library is somewhat of an experiment to see what a push style API might look like in dr_flac).
*/
#ifndef rflac_h
#define rflac_h

#define RFLAC_MIN_CHANNELS              1       /* Section 1.  Introduction */
#define RFLAC_MAX_CHANNELS              8       /* Section 1.  Introduction */
#define RFLAC_MIN_SAMPLE_RATE           1       /* Section 1.  Introduction */
#define RFLAC_MAX_SAMPLE_RATE           1048576 /* Section 1.  Introduction */
#define RFLAC_MIN_BITS_PER_SAMPLE       4       /* Section 1.  Introduction */
#define RFLAC_MAX_BITS_PER_SAMPLE       32      /* Section 1.  Introduction */
#define RFLAC_MIN_BLOCK_SIZE_IN_SAMPLES 16      /* Section 5.1.  Blocking */
#define RFLAC_MAX_BLOCK_SIZE_IN_SAMPLES 65535   /* Section 5.1.  Blocking */

typedef   signed char           rflac_int8;
typedef unsigned char           rflac_uint8;
typedef   signed short          rflac_int16;
typedef unsigned short          rflac_uint16;
typedef   signed int            rflac_int32;
typedef unsigned int            rflac_uint32;
#if defined(_MSC_VER) && !defined(__clang__)
    typedef   signed __int64    rflac_int64;
    typedef unsigned __int64    rflac_uint64;
#else
    #if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)))
        #pragma GCC diagnostic push
        #pragma GCC diagnostic ignored "-Wlong-long"
        #if defined(__clang__)
            #pragma GCC diagnostic ignored "-Wc++11-long-long"
        #endif
    #endif
    typedef   signed long long  rflac_int64;
    typedef unsigned long long  rflac_uint64;
    #if defined(__clang__) || (defined(__GNUC__) && (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 6)))
        #pragma GCC diagnostic pop
    #endif
#endif
typedef rflac_uint8 rflac_bool8;

#define RFLAC_TRUE  1
#define RFLAC_FALSE 0

typedef struct
{
    rflac_uint32 sampleRate;
    rflac_uint32 channels;
    rflac_uint32 pcmFrameCount;
    rflac_int32 pcm[RFLAC_MAX_CHANNELS][RFLAC_MAX_BLOCK_SIZE_IN_SAMPLES];
} rflac_frame;

typedef struct
{
    rflac_uint8 bitsPerSample;
    rflac_uint32 sampleRate;
    rflac_uint32 channels;
    rflac_uint64 totalPCMFrameCount;
    rflac_uint16 minBlockSize;  /* For internal use. In PCM frames. */
    rflac_uint16 maxBlockSize;  /* For internal use. In PCM frames. */
    rflac_frame frame;  /* The current flac frame. Only read from this after calling rflac_decode_frame(). */
} rflac;

typedef enum
{
    RFLAC_SUCCESS         =  0,
    RFLAC_ERROR           = -1, /* A generic error. */
    RFLAC_INVALID_ARGS    = -2,
    RFLAC_INVALID_FILE    = -10,
    RFLAC_NOT_ENOUGH_DATA = 100 /* Returned when not enough data is supplied to rflac_decode_frame(). */
} rflac_result;

rflac_result rflac_init(rflac* pFlac, const void* pData, size_t dataSize, size_t* pBytesConsumed);
rflac_result rflac_decode_frame(rflac* pFlac, const void* pData, size_t dataSize, size_t* pBytesConsumed);

#endif  /* rflac_h */
