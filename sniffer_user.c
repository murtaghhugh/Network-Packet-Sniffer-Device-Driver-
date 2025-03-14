// =====================================
// Include Headers
// =====================================

#include <stdio.h>          // For standard I/O functions (printf, fprintf)
#include <stdlib.h>         // For general utilities (exit, atoi)
#include <fcntl.h>          // For file control (open, close)
#include <unistd.h>         // For file operations (read, write)
#include <sys/ioctl.h>      // For ioctl system call
#include <string.h>         // For string functions
#include <errno.h>          // For error handling
#include <signal.h>         // For signal handling (Ctrl+C)


// =====================================
// Definitions and Constants
// =====================================

#define DEVICE_FILE "/dev/sniffer"
#define SNIFFER_SET_FILTER _IOW('p', 1, int)

//Filter MOdes
#define FILTER_TCP 1
#define FILTER_UDP 2
#define FILTER_ALL 0

#define BUFFER_SIZE 256 


// =====================================
// Signal Handling
// =====================================

/**
 * handle_signal - Handles SIGINT (Ctrl+C) to stop packet capture.
 * 
 * @signum: Signal number.
 *
 * Sets the stop flag to 1, which will stop the capture loop.
 */
void handle_signal(int signum) {
    stop = 1;
}


// =====================================
// Set Filter Mode using IOCTL
// =====================================

/**
 * set_filter - Sets the packet filter mode via ioctl.
 *
 * @fd: File descriptor for the device file.
 * @mode: Filter mode (0 = all, 1 = TCP, 2 = UDP).
 *
 * Uses the ioctl system call to set the packet filter mode.
 * Exits if the ioctl call fails.
 */
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

/**
 * read_packets - Reads captured packets from the device file.
 *
 * @fd: File descriptor for the device file.
 *
 * Continuously reads packets from the device file and writes them to stdout.
 * Stops when the stop flag is set or a read error occurs.
 */
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
        } 

        // Write data to stdout
        write(STDOUT_FILENO, buffer, bytes_read);
    }
}


// =====================================
// Main Function
// =====================================

/**
 * main - Entry point for the packet sniffer user program.
 *
 * @argc: Argument count.
 * @argv: Argument vector (program arguments).
 *
 * Handles command line arguments, opens the device file,
 * sets the filter mode, and reads packets until stopped.
 *
 * Return: 0 on success, non-zero on failure.
 */
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
