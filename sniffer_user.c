// =====================================
// Include Headers
// =====================================

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

// =====================================
// Definitions and Constants
// =====================================

#define DEVICE_FILE "/dev/sniffer"
#define SNIFFER_SET_FILTER _IOW('p', 1, int)

// Global stop flag for signal handling
volatile sig_atomic_t stop = 0;

#define FILTER_TCP 1
#define FILTER_UDP 2
#define FILTER_ALL 0

#define BUFFER_SIZE 256 

// =====================================
// Signal Handling
// =====================================

void handle_signal(int signum) {
    stop = 1;
}

// =====================================
// Set Filter Mode
// =====================================

void set_filter(int fd, int mode) {
    if (ioctl(fd, SNIFFER_SET_FILTER, &mode) < 0) {
        perror("Failed to set filter");
        exit(EXIT_FAILURE);
    }
    printf("[INFO] Filter mode set to %d\n", mode);
}

// =====================================
// Read Captured Packets
// =====================================

void read_packets(int fd) {
    char buffer[BUFFER_SIZE];
    int bytes_read;

    while (!stop) {
        bytes_read = read(fd, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            if (errno == EINTR) {
                // Interrupted by signal
                break;
            } else {
                perror("Failed to read");
                exit(EXIT_FAILURE);
            }
        }

        // Write data to stdout
        write(STDOUT_FILENO, buffer, bytes_read);
        fflush(stdout);
    }
}

// =====================================
// Main Function
// =====================================

int main(int argc, char *argv[]) {
    int fd;
    int mode;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filter_mode>\n", argv[0]);
        fprintf(stderr, "  0 = Capture all\n");
        fprintf(stderr, "  1 = Capture TCP only\n");
        fprintf(stderr, "  2 = Capture UDP only\n");
        return EXIT_FAILURE;
    }

    mode = atoi(argv[1]);
    if (mode < 0 || mode > 2) {
        fprintf(stderr, "Invalid filter mode.\n");
        return EXIT_FAILURE;
    }

    // Open the device file
    fd = open(DEVICE_FILE, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open device file");
        return EXIT_FAILURE;
    }

    // Set signal handler for clean exit
    signal(SIGINT, handle_signal);

    // Set the filter mode using ioctl
    set_filter(fd, mode);

    printf("[INFO] Capturing packets... (Press Ctrl+C to stop)\n");
    read_packets(fd);

    // Close device file
    close(fd);

    printf("[INFO] Capture stopped.\n");
    return EXIT_SUCCESS;
}
