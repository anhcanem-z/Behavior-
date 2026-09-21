// PatchX native scan — tăng tốc quét chuỗi nhị phân bằng NEON ARM64.
// Cung cấp 2 kernel:
//   - patchx_find_all: tìm MỌI vị trí của mẫu byte chính xác (needle).
//   - patchx_scan_runs: tìm các dải byte liên tục nằm trong khoảng [lo, hi]
//     (dùng cho quét chuỗi ASCII in được), tối ưu 16 byte/lần bằng NEON.
// Trên kiến trúc khác ARM64 sẽ tự rơi về vòng lặp C thuần (memchr).

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(__aarch64__)
#include <arm_neon.h>
#endif

#if defined(__aarch64__)
/* Chuyển vector so sánh 16 byte (0xFF = khớp) thành bitmask 16 bit. */
static inline uint16_t neon_mask_from_bytes(uint8x16_t m) {
    uint8x16_t shifted = vshrq_n_u8(m, 7);            /* 0x01 ở byte khớp */
    const uint8_t weights[16] = {1, 2, 4, 8, 16, 32, 64, 128,
                                 1, 2, 4, 8, 16, 32, 64, 128};
    uint8x16_t prod = vmulq_u8(shifted, vld1q_u8(weights));
    uint8x8_t p = vpadd_u8(vget_low_u8(prod), vget_high_u8(prod));
    p = vpadd_u8(p, p);
    p = vpadd_u8(p, p);
    return (uint16_t)vget_lane_u16(vreinterpret_u16_u8(p), 0);
}

static inline uint16_t neon_eq_mask_u8(uint8x16_t v, uint8_t b) {
    return neon_mask_from_bytes(vceqq_u8(v, vdupq_n_u8(b)));
}

static inline uint16_t neon_range_mask_u8(uint8x16_t v, uint8_t lo, uint8_t hi) {
    uint8x16_t m = vandq_u8(vcgeq_u8(v, vdupq_n_u8(lo)),
                            vcleq_u8(v, vdupq_n_u8(hi)));
    return neon_mask_from_bytes(m);
}

/* Kiểm tra nhanh có/tất-cả bằng reduction 1 lệnh — tránh dựng bitmask
   khi không cần, giúp nhánh nóng chạy sát băng thông bộ nhớ. */
static inline int neon_any_eq(uint8x16_t v, uint8_t b) {
    return vmaxvq_u8(vceqq_u8(v, vdupq_n_u8(b))) != 0;
}

static inline uint8x16_t neon_range_vec(uint8x16_t v, uint8_t lo, uint8_t hi) {
    return vandq_u8(vcgeq_u8(v, vdupq_n_u8(lo)),
                    vcleq_u8(v, vdupq_n_u8(hi)));
}

static inline int neon_any_range(uint8x16_t v, uint8_t lo, uint8_t hi) {
    return vmaxvq_u8(neon_range_vec(v, lo, hi)) != 0;
}

static inline int neon_all_range(uint8x16_t v, uint8_t lo, uint8_t hi) {
    return vminvq_u8(neon_range_vec(v, lo, hi)) == 0xFFu;
}
#endif

int patchx_find_all(const unsigned char* hay, long haylen,
                    const unsigned char* needle, long needlelen,
                    long* offsets, int max_matches) {
    if (needlelen <= 0 || haylen < needlelen || max_matches <= 0 ||
        !hay || !needle || !offsets) {
        return 0;
    }
    int count = 0;
    const unsigned char* p = hay;
    const unsigned char* end = hay + haylen - needlelen + 1;

#if defined(__aarch64__)
    while (p + 16 <= end && count < max_matches) {
        if (neon_any_eq(vld1q_u8(p), needle[0])) {
            uint16_t mask = neon_eq_mask_u8(vld1q_u8(p), needle[0]);
            while (mask && count < max_matches) {
                int bit = __builtin_ctz((unsigned int)mask);
                const unsigned char* cand = p + bit;
                if (cand < end &&
                    memcmp(cand, needle, (size_t)needlelen) == 0) {
                    offsets[count++] = (long)(cand - hay);
                }
                mask &= (uint16_t)(mask - 1);
            }
        }
        p += 16;
    }
#endif

    while (p < end && count < max_matches) {
        const unsigned char* q =
            (const unsigned char*)memchr(p, needle[0], (size_t)(end - p));
        if (!q) {
            break;
        }
        if (memcmp(q, needle, (size_t)needlelen) == 0) {
            offsets[count++] = (long)(q - hay);
        }
        p = q + 1;
    }
    return count;
}

long patchx_scan_runs(const unsigned char* data, long len,
                      uint8_t lo, uint8_t hi, long min_run,
                      long* runs, long max_runs) {
    if (!data || len <= 0 || min_run <= 0 || !runs || max_runs <= 0) {
        return 0;
    }
    long count = 0;
    long i = 0;

    while (i < len && count < max_runs) {
        /* 1. Tìm byte đầu tiên nằm trong khoảng. */
        long pos = i;
        int found = 0;
#if defined(__aarch64__)
        while (pos + 16 <= len) {
            uint8x16_t chunk = vld1q_u8(data + pos);
            if (neon_any_range(chunk, lo, hi)) {
                uint16_t mask = neon_range_mask_u8(chunk, lo, hi);
                pos += __builtin_ctz((unsigned int)mask);
                found = 1;
                break;
            }
            pos += 16;
        }
#endif
        if (!found) {
            while (pos < len && (data[pos] < lo || data[pos] > hi)) {
                pos++;
            }
            if (pos >= len) {
                break;
            }
        }

        long start = pos;
        long j = start + 1;

        /* 2. Kéo dài dải cho tới byte đầu tiên nằm ngoài khoảng. */
#if defined(__aarch64__)
        while (j + 16 <= len) {
            uint8x16_t chunk = vld1q_u8(data + j);
            if (!neon_all_range(chunk, lo, hi)) {
                uint16_t m = neon_range_mask_u8(chunk, lo, hi);
                uint16_t inv = (uint16_t)(~m);
                j += __builtin_ctz((unsigned int)inv);
                break;
            }
            j += 16;
        }
#endif
        while (j < len && data[j] >= lo && data[j] <= hi) {
            j++;
        }

        long run_len = j - start;
        if (run_len >= min_run) {
            runs[count * 2] = start;
            runs[count * 2 + 1] = run_len;
            count++;
        }
        i = j + 1;
    }
    return count;
}
