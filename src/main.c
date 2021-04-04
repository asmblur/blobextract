#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "endian-utils.h"
#include "utils.h"
#include <limits.h> /* PATH_MAX */
#include <stdio.h>
#include <stdlib.h>

void printUsage(const char *exec)
{
    eprintf("usage: %s BLOBFILE [OUTDIR]\n", exec);
}

typedef struct FileInfo_st_
{
	char *path;
	char *name;
	uint32_t offs;
	uint32_t size;
} FileInfo_t;

FileInfo_t files[32];
int n_files = 0;

char *dirname(const char *fname)
{
	char *dn = realpath(fname, NULL);
	return dn;
}

int main(int argc, char *argv[])
{
	char tmp[PATH_MAX];
    int ret = 1;
    char *in_name = NULL;
    char *outdir = ".";
    int i;
    uint8_t *inbuf = NULL, *p;
    int64_t insize = 0;
    uint32_t offs = 0;
    uint8_t nfiles;
    
    memset(&files, 0, sizeof(files));
    
    in_name = argv[1];
    if(load_file(in_name, 0, &insize, &inbuf) != 0)
    {
		goto END;
	}
	
    if(argc >= 3)
    {
		outdir = strdup(argv[2]);
		if(outdir[strlen(outdir)-1] == '/') outdir[strlen(outdir)-1] = '\0';
		
		if(make_dir(outdir) != 0)
		{
			eprintf("Failed to create output directory \"%s\"\n", outdir);
			goto END;
		}
	}
	
	nfiles = inbuf[0];
	p = inbuf+1;
	for(i = 0; i < nfiles; i++)
	{
		p += 2;
		uint32_t sz = ((p[0] <<  0) | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
		p += 4;

		files[n_files].size = U32FROMBE(sz);

//		printf("Size: 0x%08" PRIX32 "(%" PRId32 ")/0x%08" PRIX32 "(%" PRId32 ")\n", sz, sz, files[n_files].size, files[n_files].size);

		files[n_files].offs = offs;
		offs += files[n_files].size;
		offs = ((offs + 15) / 16) * 16;

		char *s = strdup((const char *) p);
		char *t = strrchr(s, '/');
		*(t++) = '\0';
		
		files[n_files].path = s;
		files[n_files].name = t;
		while(*(p++) != '\0');
		n_files++;
	}
	
	p++;
	offs = (uint32_t) (p - inbuf);
	offs = ((offs + 15) / 16) * 16;

	for(i = 0; i < n_files; i++)
	{
		files[i].offs += offs;
	}
	
	for(i = 0; i < n_files; i++)
	{
		strcpy(tmp, outdir);
		if(files[i].path[0] != '/')
			strcat(tmp, "/");
		strcat(tmp, files[i].path);
		
		if(make_dir(tmp) != 0)
		{
			eprintf("Failed to create output directory \"%s\"\n", tmp);
			goto END;
		}

		strcat(tmp, "/");
		strcat(tmp, files[i].name);
		
		if(save_file(inbuf + files[i].offs, files[i].size, tmp) != 0)
		{
			goto END;
		}
/*		
		printf("File %d:\n", i);
		printf("Path: \"%s\"\n", files[i].path);
		printf("Name: \"%s\"\n", files[i].name);
		printf("Offs: 0x%08" PRIX32 "(%" PRId32 ")\n", files[i].offs, files[i].offs);
		printf("Size: 0x%08" PRIX32 "(%" PRId32 ")\n", files[i].size, files[i].size);
		*/
	}

    ret = 0;
END:
	for(i = 0; i < n_files; i++)
	{
		free(files[i].path);
	}
	
	if(strcmp(outdir, ".") != 0) free(outdir);
	
    if(inbuf) free(inbuf);

    return ret;
}
