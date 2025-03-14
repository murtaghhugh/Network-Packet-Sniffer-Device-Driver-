#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#define DEVICE_FILE "/dev/sniffer"
#define SNIFFER_SET_FILTER _IOW('p', 1, int)

#define FILTER_TCP 1
#define FILTER_UDP 2
#define FILTER_ALL 0

#define BUFFER_SIZE 256

volatile sig_atomic_t stop;

void handle_signal(int signum) {
    stop = 1;
}

void set_filter(int fd, int mode) {
    if (ioctl(fd, SNIFFER_SET_FILTER, &mode) < 0) {
        perror("Failed to set filter");
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Filter mode set to %d\n", mode);
}

void read_packets(int fd) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while (!stop) {
        bytes_read = read(fd, buffer, BUFFER_SIZE);
        if (bytes_read < 0) {
            if (errno == EINTR) {
                // Interrupted by signal
                break;
            }
            perror("Failed to read");
            exit(EXIT_FAILURE);
        } else if (bytes_read == 0) {
            printf("[INFO] No data available\n");
            sleep(1);
        } else {
            buffer[bytes_read] = '\0';  // Null-terminate buffer
            printf("%s", buffer);
            fflush(stdout);
        }
    }
}

int main(int argc, char *argv[]) {
    int fd;
    int mode = FILTER_ALL;

    if (argc < 2) {
        printf("Usage: %s <filter_mode>\n", argv[0]);
        printf("  0 = Capture all\n");
        printf("  1 = Capture TCP only\n");
        printf("  2 = Capture UDP only\n");
        return EXIT_FAILURE;
    }

    mode = atoi(argv[1]);

    // Open device
    fd = open(DEVICE_FILE, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device");
        return EXIT_FAILURE;
    }

    // Set filter mode
    set_filter(fd, mode);

    // Handle Ctrl + C to stop capture cleanly
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("[INFO] Starting packet capture...\n");

    // Start reading packets
    read_packets(fd);

    printf("\n[INFO] Stopping packet capture\n");

    // Close device
    close(fd);

    return EXIT_SUCCESS;
}
