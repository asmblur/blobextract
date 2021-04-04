#ifndef _UTILS_H_
#define _UTILS_H_

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

extern uint32_t __verbosity_flags;
extern uint32_t __verbosity_level;

#define VERBOSITY_FLAG_ERROR    (1 <<  0)
#define VERBOSITY_FLAG_WARN     (1 <<  1)
#define VERBOSITY_FLAG_INFO     (1 <<  2)
#define VERBOSITY_FLAG_DEBUG    (1 <<  3)

#define VERBOSITY_SILENT    0
#define VERBOSITY_ERROR     1
#define VERBOSITY_WARN      2
#define VERBOSITY_INFO      3
#define VERBOSITY_DEBUG     4
#define VERBOSITY_MAX       10

#define MAX_DATA_SIZE (MAXPATHLEN)

#define eprintf(...) if(((__verbosity_flags & VERBOSITY_FLAG_ERROR) != 0) && (__verbosity_level >= VERBOSITY_ERROR)) { fprintf (stderr, __VA_ARGS__); } else { }
#define wprintf(...) if(((__verbosity_flags & VERBOSITY_FLAG_WARN) != 0) && (__verbosity_level >= VERBOSITY_WARN)) { fprintf (stderr, __VA_ARGS__); } else { }
#define iprintf(...) if(((__verbosity_flags & VERBOSITY_FLAG_INFO) != 0) && (__verbosity_level >= VERBOSITY_INFO)) { fprintf (stdout, __VA_ARGS__); } else { }
#define dprintf(__lvl, ...) if(((__verbosity_flags & VERBOSITY_FLAG_DEBUG) != 0) && (__verbosity_level >= (VERBOSITY_DEBUG + ((__lvl) - 1)))) { fprintf (stdout, __VA_ARGS__); } else { }

uint32_t _strto32(const char *s, uint32_t *res, int base);

int file_exists(const char *fname);
int64_t file_length(const char *fname);

int64_t fileSize(FILE *fp);
void hexdump(uint32_t offset, void *data, uint32_t len);

#define SEARCH_BACKWARD     (1 <<  0)
#define SEARCH_REVERSE      (1 <<  1)

int make_dir(const char *name);

int64_t buffered_file_copy(FILE *in, int64_t in_offset, int64_t sz, FILE *out, uint64_t out_offset);
int copy_file_content(const char *inname, int64_t in_offset, int64_t sz, const char *outname, uint64_t out_offset);

int copy_file(const char *src, const char *dst);
int fpokeu8(FILE *fp, int64_t pos, uint8_t v);
int fpeeku32le(FILE *fp, int64_t pos, void *p);
int fpokeu32le(FILE *fp, int64_t pos, uint32_t v);

int64_t find_pattern(FILE *in, int64_t start, int64_t sz, const void *pattern, const void *mask, int64_t plen, int64_t step, uint32_t flags);
int load_buf(FILE *fp, int64_t offset, int64_t sz, void **p_buf);
int load_file(const char *fname, int64_t offset, int64_t *size, uint8_t **p_buf);
int load_file_string(const char *fname, int64_t offset, int64_t *size, uint8_t **p_buf);
int is_valid_filename_char(int ch);
int64_t filename_strlen(const char *s, int64_t max);
char *copy_string(const char *s);
int save_file(const void *data, uint64_t sz, const char *outname);

#endif // #ifndef _UTILS_H_
