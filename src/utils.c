#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/param.h>
#include "utils.h"
#include "endian-utils.h"

uint32_t __verbosity_flags = (VERBOSITY_FLAG_WARN | VERBOSITY_FLAG_INFO | VERBOSITY_FLAG_ERROR | VERBOSITY_FLAG_DEBUG);
uint32_t __verbosity_level = VERBOSITY_INFO;

#define _toupper(x) ((((x) >= 'a') && ((x) <= 'z')) ? ((x) - 0x20) : (x))

uint32_t _strto32(const char *s, uint32_t *res, int base)
{
	int i;
	uint32_t result = 0;
    char tmp[32] = "\0";

    if(base == 0)
    {
        if(strncasecmp(s, "0x", 2) == 0)
        {
            base = 16;
            strncpy(tmp, s + 2, sizeof(tmp)-1);
            tmp[sizeof(tmp)-1] = '\0';
        }
        else
        {
            for(i = 0; s[i] != '\0'; i++)
            {
                if((_toupper(s[i]) >= 'A') && (_toupper(s[i]) <= 'F'))
                {
                    base = 16;
                    break;
                }
            }

            strncpy(tmp, s, sizeof(tmp)-1);
            tmp[sizeof(tmp)-1] = '\0';

            if(_toupper(tmp[strlen(tmp)-1]) == 'h')
            {
                base = 16;
                tmp[strlen(tmp)-1] = '\0';
            }

            if(base == 0) base = 10;
        }
    }
    else if(base == 16)
    {
        if(strncasecmp(s, "0x", 2) == 0)
        {
            strncpy(tmp, s + 2, sizeof(tmp)-1);
            tmp[sizeof(tmp)-1] = '\0';
        }
        else
        {
            strncpy(tmp, s, sizeof(tmp)-1);
            tmp[sizeof(tmp)-1] = '\0';

            if(_toupper(tmp[strlen(tmp)-1]) == 'h')
            {
                base = 16;
                tmp[strlen(tmp)-1] = '\0';
            }            
        }
    }

    switch(base)
    {
        case 10:
        {
            for(i = 0; tmp[i] != '\0'; i++)
            {
                result *= 10;
                if((tmp[i] >= '0') && (tmp[i] <= '9'))
                {
                    result += tmp[i] - '0';
                }
                else
                {
                    return -1;
                }
            }
            break;
        }
        case 16:
        {
            for(i = 0; tmp[i] != '\0'; i++)
            {
                result <<= 4;
                if((tmp[i] >= '0') && (tmp[i] <= '9'))
                {
                    result += tmp[i] - '0';
                }
                else if((_toupper(tmp[i]) >= 'A') && (_toupper(tmp[i]) <= 'F'))
                {
                    result += 10 + (_toupper(tmp[i]) - 'A');
                }
                else
                {
                    return -1;
                }
            }
            break;
        }
        default:
        {
            eprintf("Unsupported base: %d\n", base);
            return -1;
        }
    }

	if(res) *res = result;
	
	return 0;
}

int file_exists(const char *fname)
{
    struct stat sb;
    return(stat(fname, &sb) != -1);
}

int64_t file_length(const char *fname)
{
    struct stat sb;
    
    if(stat(fname, &sb) == -1)
    {
        return (int64_t) -1;
    }
    
    return (int64_t) sb.st_size;
}

int64_t fileSize(FILE *fp)
{
    int64_t old, sz;
    old = ftello(fp);
    if(fseeko(fp, 0, SEEK_END) == -1) return -1;
    sz = ftello(fp);
    if(fseeko(fp, old, SEEK_SET) == -1) return -2;
    return sz;
}
    
int copy_file(const char *src, const char *dst)
{
    FILE *in = NULL, *out = NULL;
    int ret = -1;
    int64_t buf_sz = (1024 * 32), nleft;
    uint8_t *buf = NULL;
    
    if((in = fopen(src, "rb")) == NULL)
    {
        fprintf(stderr, "ERROR: failed opening file \"%s\" for reading\n", src);
        goto END;
    }

    nleft = fileSize(in);

    if((out = fopen(dst, "wb")) == NULL)
    {
        fprintf(stderr, "ERROR: failed opening file \"%s\" for writing\n", dst);
        goto END;
    }

    if((buf = (uint8_t *) malloc(buf_sz)) == NULL)
    {
        fprintf(stderr, "ERROR: failed allocating copy buffer\n");
        goto END;
    }
    
    while(nleft > 0)
    {
        int64_t n = (nleft > buf_sz) ? buf_sz : nleft;
        int64_t r;
        
        r = fread(buf, 1, n, in);
        if(r != n)
        {
            fprintf(stderr, "ERROR: failed reading %" PRId64 " bytes into copy buffer\n", n);
            goto END;
        }

        r = fwrite(buf, 1, n, out);
        if(r != n)
        {
            fprintf(stderr, "ERROR: failed writing %" PRId64 " bytes from copy buffer\n", n);
            goto END;
        }
        
        nleft -= n;
    }
    
    ret = 0;
    
END:
    if(in) fclose(in);
    if(out) fclose(out);
    if(buf) free(buf);
    
    return ret;
}

int64_t find_patternx(FILE *fp, int64_t pos, int64_t sz, const void *pattern_d, const void *pattern_m, int64_t pattern_sz, int64_t step)
{
    int64_t ret = -1;
    int64_t buf_sz = (1024 * 32);
    uint8_t *buf = NULL;
    int64_t f_pos = pos, f_nrem = 0, b_pos = 0, b_nrem = 0;
    int64_t i;
            
    if((buf = (uint8_t *) malloc(buf_sz)) == NULL)
    {
        fprintf(stderr, "ERROR: failed allocating copy buffer\n");
        goto END;
    }
    
    f_nrem = fileSize(fp) - f_pos;
    
    while((b_nrem + f_nrem) >= pattern_sz)
    {
        if(b_nrem < pattern_sz)
        {
            f_nrem += b_nrem;
            f_pos -= b_nrem;
            
            int64_t n = (f_nrem > buf_sz) ? buf_sz : f_nrem;
            if(fseeko(fp, f_pos, SEEK_SET) == -1)
            {
                fprintf(stderr, "ERROR: failed seeking to file position 0x%08" PRIX64 "(%" PRId64 ")\n", f_pos, f_pos);
                goto END;
            }
            
            int64_t r = fread(buf, 1, n, fp);
            if(r != n)
            {
                fprintf(stderr, "ERROR: failed reading 0x%08" PRIX64 "(%" PRId64 ") bytes at file position 0x%08" PRIX64 "(%" PRId64 ")\n", n, n, f_pos, f_pos);
                goto END;
            }
            
            f_pos += n;
            f_nrem -= n;
            b_pos = 0;
            b_nrem = n;
            continue;
        }
        
        for(i = 0; i < pattern_sz; i++)
        {
            if((((uint8_t *) pattern_d)[i] & ((uint8_t *) pattern_m)[i]) != (buf[b_pos + i] & ((uint8_t *) pattern_m)[i])) break;
        }
        
        if(i >= pattern_sz)
        {
            ret = f_pos - b_pos;
            goto END;
        }
        
        b_pos += step;
        b_nrem -= step;
    }
    
END:
    if(buf) free(buf);
    return ret;
}

int fpokeu8(FILE *fp, int64_t pos, uint8_t v)
{
    int ret = -1;
    int64_t n = sizeof(v);
    int64_t r;
    
    if(fseeko(fp, pos, SEEK_SET) == -1)
    {
        fprintf(stderr, "ERROR: failed seeking to file position 0x%08" PRIX64 "(%" PRId64 ")\n", pos, pos);
        goto END;
    }
       
    r = fwrite(&v, 1, n, fp);
    if(r != n)
    {
        fprintf(stderr, "ERROR: failed writing 0x%08" PRIX64 "(%" PRId64 ") bytes at file position 0x%08" PRIX64 "(%" PRId64 ")\n", n, n, pos, pos);
        goto END;
    }
    
    ret = 0;
    
END:
    return ret;
}

int fpeeku32le(FILE *fp, int64_t pos, void *p)
{
    int ret = -1;
    int64_t n = sizeof(uint32_t);
    int64_t r;
    uint32_t v = 0;
    
    if(fseeko(fp, pos, SEEK_SET) == -1)
    {
        fprintf(stderr, "ERROR: failed seeking to file position 0x%08" PRIX64 "(%" PRId64 ")\n", pos, pos);
        goto END;
    }
    
    r = fread(&v, 1, n, fp);
    if(r != n)
    {
        fprintf(stderr, "ERROR: failed reading 0x%08" PRIX64 "(%" PRId64 ") bytes at file position 0x%08" PRIX64 "(%" PRId64 ")\n", n, n, pos, pos);
        goto END;
    }
    
    *(uint32_t *) (p) = U32FROMLE(v);
    
    ret = 0;
    
END:
    return ret;
}

int fpokeu32le(FILE *fp, int64_t pos, uint32_t v)
{
    int ret = -1;
    int64_t n = sizeof(uint32_t);
    int64_t r;
    uint32_t v2;
    
    if(fseeko(fp, pos, SEEK_SET) == -1)
    {
        fprintf(stderr, "ERROR: failed seeking to file position 0x%08" PRIX64 "(%" PRId64 ")\n", pos, pos);
        goto END;
    }
    
    v2 = U32TOLE(v);
    
    r = fwrite(&v2, 1, n, fp);
    if(r != n)
    {
        fprintf(stderr, "ERROR: failed writing 0x%08" PRIX64 "(%" PRId64 ") bytes at file position 0x%08" PRIX64 "(%" PRId64 ")\n", n, n, pos, pos);
        goto END;
    }
    
    ret = 0;
    
END:
    return ret;
}

void hexdump(uint32_t offset, void *data, uint32_t len)
{
	uint32_t i;
	
	printf("         00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F");
	
	if((offset % 16) != 0)
	{
		printf("\n%08X", offset & 0xFFFFFFF0);
		for(i = 0; i < (offset & 0x0F); i++)
			printf(" ??");
	}
		
	for(i = 0; i < len; i++)
	{
		uint32_t addr = offset + i;
		if((addr % 16) == 0)
			printf("\n%08X", addr);
		
		printf(" %02X", ((uint8_t *) data)[i]);
	}
	printf("\n");
}

int64_t find_pattern(FILE *in, int64_t start, int64_t sz, const void *pattern, const void *mask, int64_t plen, int64_t step, uint32_t flags)
{
    uint8_t *patbuf = NULL, *maskbuf = NULL;
    uint8_t *p_pattern = NULL, *p_mask = NULL;
    uint8_t *buf = NULL;
    uint32_t buf_sz = 32 * 1024 * 1024;
    int64_t i, ret = -1;
    int64_t buf_foffs;
    
    // make sure our buffer is large enough to hold the entire pattern.
    if(buf_sz < plen) buf_sz = plen;
    
    if((mask != NULL) && (flags & SEARCH_REVERSE))
    {
        // if a mask was supplied *and* the "reverse" flag is set, create a new buffer and populate it with
        //  the mark data, in reverse order.
        if((maskbuf = (uint8_t *) malloc(plen)) == NULL)
        {
            eprintf("ERROR: Failed to allocate %" PRId64 " bytes of memory for mask buffer.\n", plen);
            goto END;
        }

        // copy the mask into the new buffer, but reverse the order(last byte becomes the first)
        for(i = 0; i < plen; i++)
        {
            maskbuf[i] = ((uint8_t *) mask)[plen - (i+1)];
        }            
        
        p_mask = ((uint8_t *) maskbuf);
    }
    else
    {
        // if no mask was specified or the "reverse" flag isn't set, we can use the existing mask buffer(or NULL)
        p_mask = (uint8_t *) mask;
    }
    
    // if either a mask was specified or the "reverse" flag is set, we'll need a create a work buffer and populate it
    //  with the pre-modified pattern data(i.e. with mask and/or reversal of byte order operations applied).
    if((p_mask != NULL) || (flags & SEARCH_REVERSE))
    {
        if((patbuf = (uint8_t *) malloc(plen)) == NULL)
        {
            eprintf("ERROR: Failed to allocate %" PRId64 " bytes of memory for pattern buffer.\n", plen);
            goto END;
        }
        p_pattern = patbuf;

        if(flags & SEARCH_REVERSE)
        {
            // the "reverse" flag is set
            
            if(p_mask != NULL)
            {
                // populate the new buffer with the pattern data, masked and in reverse order.
                for(i = 0; i < plen; i++)
                {
                    p_pattern[i] = ((uint8_t *) pattern)[plen - (i+1)] & p_mask[i];
                }
            }
            else
            {
                // no mask specified, just populate the new buffer with the reversed pattern data.
                for(i = 0; i < plen; i++)
                {
                    p_pattern[i] = ((uint8_t *) pattern)[plen - (i+1)];
                }
            }
        }
        else
        {
            // mask specified, not reversed.  populate the new buffer with the masked pattern data.
            for(i = 0; i < plen; i++)
            {
                p_pattern[i] = ((uint8_t *) pattern)[i] & p_mask[i];
            }
        }
    }
    else
    {
        // if we need not reverse or mask the pattern data, we can use the pattern data buffer as-is
        p_pattern = ((uint8_t *) pattern);
    }

    int64_t fsz = fileSize(in);

    // a negative starting offset is from the end of the file.
    if(start < 0)
    {
        if(abs(start) >= fsz)
        {
            eprintf("ERROR: negative offset %" PRId64 " is larger than the file size, %" PRId64 "\n", start, fsz);
            goto END;
        }
        
        buf_foffs = fsz + start;
    }
    else
    {
        if(start >= fsz)
        {
            eprintf("ERROR: offset %" PRId64 " is larger than the file size, %" PRId64 "\n", start, fsz);
            goto END;
        }
        
        buf_foffs = start;
    }
    
    if(fseeko(in, buf_foffs, SEEK_SET) != 0)
    {
        eprintf("ERROR: Failed to seek to offset 0x%08" PRIX64 " in input file.\n", buf_foffs);
        goto END;
    }
    
    if((buf = (uint8_t *) malloc(buf_sz)) == NULL)
    {
        eprintf("ERROR: Failed to allocate %d bytes of memory for buffer.\n", buf_sz);
        goto END;
    }
    
    if(sz < 0) sz = (flags & SEARCH_BACKWARD) ? buf_foffs : (fsz - buf_foffs);
    
    int64_t buf_offs = 0;
    int64_t buf_lvl = 0;
    int64_t min_lvl = plen;
    int64_t fremain = sz;
    
    while(1)
    {
        // calculate the number of bytes remain in the buffer
        int64_t bremain = (buf_lvl - buf_offs);

        // when the data remaining in the buffer is less than the minimum level, try to load some more from the file
        if(bremain < min_lvl)
        {
        
            // when the data remaining in the file addeded combined with that in the buffer are still less than the minimum,
            //  greak out of the loop(fail)
            if((fremain + bremain) < min_lvl) break;
        
            // calc the number of bytes we can load from the file to add to the buffer
            int64_t toread = (buf_sz - bremain);
            int64_t offs = 0;
            
            // don't overflow the buffer by loading more data than will fill it.
            if(toread > fremain) toread = fremain;

            if(bremain > 0)
            {
                if(flags & SEARCH_BACKWARD)
                {
                    // shift the remaining data to make room at the start of the buffer
                    //  for new data from the file.
                    memmove(buf + toread, buf, bremain);
                }
                else
                {
                    // move the "buf_nremain" bytes to buf[0..buf_nremain-1], leaving
                    //  buf[buf_nremain..buf_sz-1] as "buf_nfree".  Use fread(buf + buf_nremain, 1, nload, in);
                    //  "nload" is the number to read from the file into the buffer.
                    //  // 
                    //  n = min(file_nremain, buf_nfree);
                    //  fread(buf + buf_nremain, 1, n, in);
                    //  buf_nremain += n; // add n to the count of bytes that remain in the buffer
                    //  file_nremain -= n; // sub n from the count of bytes that remain in the file.
                    //  
                    //(buf_nfree > file_nremain) ? file_nremain : bf_nfree.  
                    
                    // the remaining data to the buffer start. buf_nfree = (buf_sz - buf_nremain).  fread(buf + buf_nremain, 1, (buf_nfree > file_nremain) ? file_nremain : buf_nfree, in);
                    // so that the buffer is empty from offset "nremain" to the
                    //  end of the buffer.  New data can then be read from the
                    //  file directly to the buffer offset "nremain".  buffer  file can be
                    //  read directly into the buffer starting at "buf + nremain", a the buffer st a file read like "fread(buf + nremain, 1, toread, infp)" leaving the free space
                    //  as a contiguous block of the buffer to make
                    //  room for new data from the file.
                    memcpy(buf, buf + (buf_lvl - bremain), bremain);
                    offs = bremain;
                }
            }
            
            buf_lvl = bremain;
            
            if(flags & SEARCH_BACKWARD)
            {
                buf_foffs -= buf_offs;
            }
            else
            {
                buf_foffs += buf_offs;
            }

            if((ret = fseek(in, buf_foffs + offs, SEEK_SET)) != 0)
            {
                eprintf("ERROR: Failed seeking to position 0x%016" PRIX64 " in input file\n", buf_foffs + offs);
                goto END;
            }
            
            ret = fread(buf + offs, 1, toread, in);

            if(ret < 0)
            {
                eprintf("ERROR: Failed to read from input file\n");
                goto END;
            }
            
            if(ret != toread)
            {
                eprintf("ERROR: Failed reading 0x%08" PRIX64 "(%" PRId64 ") bytes from input file\n", toread, toread);
                ret = -1;
                goto END;
            }
            
            buf_offs = 0;
            buf_lvl += ret;
            fremain -= ret;
            
            continue;
        }

        uint8_t *d;
        if(flags & SEARCH_BACKWARD)
            d = (buf + (buf_lvl - (buf_offs + plen)));
        else
            d = buf + buf_offs;

        if(p_mask != NULL)
        {
            for(i = 0; i < plen; i++)
            {
                if((d[i] & p_mask[i]) != p_pattern[i])
                {
                    break;
                }
            }
            
            if(i >= plen)
            {
                ret = buf_foffs + (d - buf);
                goto END;
            }
        }
        else
        {
            if(memcmp(d, p_pattern, plen) == 0)
            {
                ret = buf_foffs + (d - buf);
                goto END;
            }
        }

        buf_offs += step;        
    }

    ret = -1;

END:    
    if(patbuf) free(patbuf);
    if(maskbuf) free(maskbuf);
    if(buf) free(buf);

    return ret;
}


int make_dir(const char *name)
{
    int ret;
    
    if(((ret = mkdir(name, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH)) != 0) && (errno != EEXIST))
    {
        return 1;
    }
    
    return 0;
}

int64_t buffered_file_copy(FILE *in, int64_t in_offset, int64_t sz, FILE *out, uint64_t out_offset)
{
    int64_t ncopied = 0, nrem = sz;
    int ret = 0;
    int64_t buf_sz = (4 * 1024 * 1024);
    uint8_t *buf = NULL;
    
//    printf("copy 0x%08" PRIX64 " bytes from 0x%08" PRIX64 "\n", sz, in_offset);
        
    if(in_offset > 0)
    {
        if(fseek(in, in_offset, SEEK_SET) != 0)
        {
            eprintf("Failed to seek to file offset 0x%08" PRIX64 "(%" PRId64 ") of input file\n", in_offset, in_offset);
            ret = -1;
            goto END;
        }
    }
        
    if((buf = (uint8_t *) malloc(buf_sz)) == NULL)
    {
        eprintf("Out of memory\n");
        ret = -1;
        goto END;
    }
    
    if(out_offset > 0)
    {
        int64_t outsize = fileSize(out);
        
        if(outsize == (int64_t) -1)
        {
            outsize = 0;
        }
        
        if(out_offset > outsize)
        {
            // if an offset beyond the end of the output file was specified, pad
            //  the file with 00s.
            
            memset(buf, 0, buf_sz);
            int64_t npad = (out_offset - outsize);
                        
            while(npad > 0)
            {
                int n = (npad > buf_sz) ? buf_sz : npad;
                fwrite(buf, 1, n, out);
                npad -= n;
            }
        }
        else
        {
            if(fseek(out, out_offset, SEEK_SET) != 0)
            {
                eprintf("Failed to seek to file offset 0x%08" PRIX64 "(%" PRId64 ") of output file\n", out_offset, out_offset);
                ret = -1;
                goto END;
            }
        }
    }
    
    // read data from "in" and write it to "out", one bufferful at a time   
    while(nrem > 0)
    {
        int n = (int) ((nrem > buf_sz) ? buf_sz : nrem);
        ret = fread(buf, 1, n, in);
        if(ret != n)
        {
            eprintf("Failed to read 0x%08" PRIX32 "(%" PRId32 ") bytes from input file\n", n, n);
            ret = -1;
            goto END;
        }
        
        ret = fwrite(buf, 1, n, out);
        if(ret != n)
        {
            eprintf("Failed to write 0x%08" PRIX32 "(%" PRId32 ") bytes from input file\n", n, n);
            ret = -1;
            goto END;
        }
        
        nrem -= n;
        ncopied += n;
    }
    
    // return the total number of bytes copied
    ret = ncopied;
    
END:
    if(buf) free(buf);

    return ret;
}

int copy_file_content(const char *inname, int64_t in_offset, int64_t sz, const char *outname, uint64_t out_offset)
{
    FILE *in, *out;
    int64_t nleft = sz;
//    int ret = 0;
    int64_t data_size = (32 * 1024 * 1024);
    uint8_t *data;
    
    printf("copy 0x%08" PRIX64 " bytes from 0x%08" PRIX64 "\n", sz, in_offset);
        
    if((in = fopen(inname, "rb")) == NULL)
    {
        eprintf("Failed to open input file \"%s\" for reading.\n", inname);
        return -1;
    }

    if(in_offset > 0)
    {
        if(fseek(in, in_offset, SEEK_SET) != 0)
        {
            fclose(in);
            return -1;
        }
    }
    
    if((data = (uint8_t *) malloc(data_size)) == NULL)
    {
        fclose(in);
        return -1;
    }
    
    if(out_offset > 0)
    {
        int64_t outsize = file_length(outname);
        
        if(outsize == (int64_t) -1)
        {
            outsize = 0;
        }
        
        if(out_offset >= outsize)
        {
            memset(data, 0, data_size);
            int64_t npad = (out_offset - outsize);
            
            if((out = fopen(outname, "ab+")) == NULL)
            {
                free(data);
                fclose(in);
                eprintf("Failed to open output file \"%s\" for writing.\n", outname);
                return 1;
            }
            
            while(npad > 0)
            {
                int n = (npad > data_size) ? data_size : npad;
                fwrite(data, 1, n, out);
                npad -= n;
            }
        }
        else
        {
            if((out = fopen(outname, "rb+")) == NULL)
            {
                free(data);
                fclose(in);
                eprintf("Failed to open output file \"%s\" for writing.\n", outname);
                return -1;
            }
            
            if(fseek(out, out_offset, SEEK_SET) != 0)
            {
                free(data);
                fclose(in);
                return -1;
            }
        }
    }
    else
    {
        if((out = fopen(outname, "wb")) == NULL)
        {
            free(data);
            fclose(in);
            eprintf("Failed to open output file \"%s\" for writing.\n", outname);
            return 1;
        }
    }
        
    while(nleft > 0)
    {
        int toRead = (int) ((nleft > data_size) ? data_size : nleft);
        
        if(fread(data, 1, toRead, in) != toRead)
        {
            free(data);
            fclose(in);
            eprintf("Failed reading from input file.\n");
            return 1;
        }

        if(fwrite(data, 1, toRead, in) != toRead)
        {
            free(data);
            fclose(in);
            eprintf("Failed writing to output file.\n");
            return 1;
        }
        
        nleft -= toRead;
    }
    
    free(data);
    fclose(out);
    fclose(in);
    return 0;
}


int save_file(const void *data, uint64_t sz, const char *outname)
{
    FILE *out;

	if((out = fopen(outname, "wb")) == NULL)
	{
		eprintf("Failed to open output file \"%s\" for writing.\n", outname);
		return 1;
	}
        
	if(fwrite(data, 1, sz, out) != sz)
	{
		fclose(out);
		eprintf("Failed writing to output file.\n");
		return 1;
	}
        
    fclose(out);
    return 0;
}

int load_file(const char *fname, int64_t offset, int64_t *size, uint8_t **p_buf)
{
    FILE *in = NULL;
    int64_t fsz;
    uint8_t *buf = NULL;
    int ret = -1;

    if(!file_exists(fname))
    {
        eprintf("ERROR: File \"%s\" not found.\n", fname);
        ret = -1;
        goto END;
    }

    fsz = file_length(fname);

    if((in = fopen(fname, "rb")) == NULL)
    {
        eprintf("ERROR: Failed to open input file \"%s\" for reading.\n", fname);
        ret = -1;
        goto END;
    }

    if(offset < 0) offset += fsz;
    
    int64_t sz = (fsz - offset);
    
    if(size && (*size != 0))
    {
        if(*size < 0)
        {
            sz = sz + *size;
        }
        else
        {
            if(*size > sz)
            {
                eprintf("ERROR: Size 0x%08" PRIX64 "(%" PRId64 ") is greater than offset file size of 0x%08" PRIX64 "(%" PRId64 ") bytes\n",
                    *size, *size, sz, sz);
                ret = -1;
                goto END;
            }
            
            sz = *size;
        }
    }
    
    if(p_buf && *p_buf)
    {
		printf("using your buf\n");
        buf = *p_buf;
    }
    else
    {    
        if((buf = (uint8_t *) malloc(sz)) == NULL)
        {
            eprintf("ERROR: Failed to allocate %" PRId64 " bytes of memory for buffer.\n", sz);
            ret = -1;
            goto END;
        }
    }

    if((ret = fseek(in, offset, SEEK_SET)) != 0)
    {
        eprintf("ERROR: Failed seeking to position 0x%08" PRIX64 "(%" PRId64 ") in input file\n", offset, offset);
        ret = -1;
        goto END;
    }
    
    ret = fread(buf, 1, sz, in);
    if(ret != sz)
    {
        eprintf("ERROR: Failed to read 0x%08" PRIX64 "(%" PRId64 ") bytes of memory for buffer.\n", sz, sz);
        ret = -1;
        goto END;
    }
  
	if(p_buf) *p_buf = buf;
//    if(p_buf && (*((uint8_t **) p_buf)) && (buf != (*((uint8_t **) p_buf)))) *((uint8_t **) p_buf) = buf;
    if(size) *size = sz;
    
    ret = 0;
    
END:
    if((ret != 0) && buf && !(p_buf && *p_buf)) free(buf);
    if(in) fclose(in);
    return ret;
}

char *copy_string(const char *s)
{
    char *news;
    int len = strlen(s);
    if((news = (char *) malloc(len + 1)) == NULL)
    {
        eprintf("out of memory\n");
        return NULL;
    }

    memcpy(news, s, len + 1);
    return news;
}

int load_file_string(const char *fname, int64_t offset, int64_t *size, uint8_t **p_buf)
{
    FILE *in = NULL;
    int64_t fsz;
    uint8_t *buf = NULL;
    int ret = -1;

    if(!file_exists(fname))
    {
        eprintf("ERROR: File \"%s\" not found.\n", fname);
        ret = -1;
        goto END;
    }

    fsz = file_length(fname);

    if((in = fopen(fname, "rb")) == NULL)
    {
        eprintf("ERROR: Failed to open input file \"%s\" for reading.\n", fname);
        ret = -1;
        goto END;
    }

    if(offset < 0) offset += fsz;
    
    int64_t sz = (fsz - offset);
    
    if(size && (*size != 0))
    {
        if(*size < 0)
        {
            sz = sz + *size;
        }
        else
        {
            if(*size > sz)
            {
                eprintf("ERROR: Size 0x%08" PRIX64 "(%" PRId64 ") is greater than offset file size of 0x%08" PRIX64 "(%" PRId64 ") bytes\n",
                    *size, *size, sz, sz);
                ret = -1;
                goto END;
            }
            
            sz = *size;
        }
    }
    
    printf("sz: %" PRIX64 "(%" PRId64 ")\n", sz, sz);
    
    if(p_buf && *p_buf)
    {
		printf("using your buf\n");
        buf = *p_buf;
    }
    else
    {    
        if((buf = (uint8_t *) malloc(sz+1)) == NULL)
        {
            eprintf("ERROR: Failed to allocate %" PRId64 " bytes of memory for buffer.\n", sz+1);
            ret = -1;
            goto END;
        }
    }
    
    printf("buf: %p\n", buf);

    if((ret = fseek(in, offset, SEEK_SET)) != 0)
    {
        eprintf("ERROR: Failed seeking to position 0x%08" PRIX64 "(%" PRId64 ") in input file\n", offset, offset);
        ret = -1;
        goto END;
    }
    
    ret = fread(buf, 1, sz, in);
    if(ret != sz)
    {
        eprintf("ERROR: Failed to read 0x%08" PRIX64 "(%" PRId64 ") bytes of memory for buffer.\n", sz, sz);
        ret = -1;
        goto END;
    }

    buf[sz] = '\0';
  
	if(p_buf) *p_buf = buf;
//    if(p_buf && (*((uint8_t **) p_buf)) && (buf != (*((uint8_t **) p_buf)))) *((uint8_t **) p_buf) = buf;
    if(size) *size = sz;
    
    ret = 0;
    
END:
    if((ret != 0) && buf && !(p_buf && *p_buf)) free(buf);
    if(in) fclose(in);
    return ret;
}


int is_valid_filename_char(int ch)
{
    if((ch < 0x20) || (ch >= 0x7F)) return 0;

    //~ if(((ch >= '0') && (ch <= '9')) || ((ch >= 'a') && (ch <= 'z')) || ((ch >= 'A') && (ch <= 'Z'))
        //~ || (ch == '_') || (ch == '-') || (ch == '.') || (ch == '\\') || (ch == '/') || (ch == '~')
        //~ || (ch == '\x20')
    //~ )

    return 1;
}

int64_t filename_strlen(const char *s, int64_t max)
{
    int64_t i;
    for(i = 0; i < max; i++)
    {
        if(!is_valid_filename_char(s[i])) break;
    }
    
    return i;
}

int load_buf(FILE *fp, int64_t offset, int64_t sz, void **p_buf)
{
    void *buf = NULL;
    int ret = -1;
    
    if(!p_buf)
    {
        eprintf("ERROR: p_buf argument to load_buf() cannot be NULL\n");
        ret = -1;
        goto END;
    }
    
    if((ret = fseek(fp, offset, SEEK_SET)) != 0)
    {
        eprintf("ERROR: Failed seeking to position 0x%08" PRIX64 " in input file\n", offset);
        ret = -1;
        goto END;
    }
    
    if(!*p_buf)
    {
        buf = malloc(sz);
        if(buf == NULL)
        {
            eprintf("ERROR: Out of memory\n");
            ret = -1;
            goto END;
        }
    }

    if((ret = fread(buf ? buf : *p_buf, 1, sz, fp)) != sz)
    {
        if(buf) free(buf);
        eprintf("ERROR: Failed reading 0x%08" PRIX64 " bytes from input file\n", sz);
        ret = -1;
        goto END;
    }
    
    if(buf) *p_buf = buf;

    ret = 0;
    
END:
    return ret;
}
