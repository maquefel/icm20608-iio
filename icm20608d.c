/** @file icm20608d.c
 *
 * @brief Main file for iio icm20608 daemon
 *
 * @par
 */

#include <syslog.h>
#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>

#include <sys/signalfd.h>
#include <sys/epoll.h>

#include <iio.h>

#include <endian.h>

#include "daemonize.h"

#ifdef DEBUG
#define debug_printf(format, ...) fprintf(stderr, "%s:%s:%d: " format, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define debug_printf_n(format, ...) debug_printf(format "\n", ##__VA_ARGS__)
#else
#define debug_printf_n(format, ...) do{} while(0)
#define debug_printf(format, ...) do{} while(0)
#endif

static int verbose_flag = 0;
static int no_daemon_flag = 0;
static int kill_flag = 0;
static int hup_flag = 0;

static int shutdown_flag = 0;

/** signal fd */
static int sigfd;

/** /dev/null fd*/
int devnullfd;

/** logging */
#ifdef DEBUG
int log_level = LOG_DEBUG;
#else
int log_level = LOG_INFO;
#endif

static char *pidFile = "/var/run/icm20608d.pid";

#define PACKAGE_NAME "icm20608d"

#define SAMPLES_PER_READ 256
#define DEFAULT_FREQ_HZ  100

static struct option long_options[] =
{
    {"verbose",         no_argument,        &verbose_flag,      'V'},
    {"version",         no_argument,        0,                  'v'},
    {"log-level",       required_argument,  0,                  'l'},
    {"n",               no_argument,        &no_daemon_flag,    'n'},
    {"kill",            no_argument,        &kill_flag,         'k'},
    {"hup",             no_argument,        &hup_flag,          'H'},
    {"pid",             required_argument,  0,                  'p'},
    {"config",          required_argument,  0,                  'c'},
    {"uri",             required_argument,  0,                  'u'},
    {"help",            no_argument,        0,                  'h'},
    {0, 0, 0, 0}
};

/**************************************************************************
 *    Function: Print Usage
 *    Description:
 *        Output the command-line options for this daemon.
 *    Params:
 *        @argc - Standard argument count
 *        @argv - Standard argument array
 *    Returns:
 *        returns void always
 **************************************************************************/
void PrintUsage(int argc, char *argv[]) {
    argv = argv;
    if(argc >=1) {
        printf(
            "-v, --version              prints version and exits\n" \
            "-V, --verbose              be more verbose\n" \
            "-l, --log-level            set log level[default=LOG_INFO]\n" \
            "-n                         don\'t fork off as daemon\n" \
            "-k, --kill                 kill old daemon instance in case if present\n" \
            "-H, --hup                  send daemon signal to reload configuration\n" \
            "-p, --pid                  path to pid file[default=%s]\n" \
            "-c, --config=FILE          configuration file[default=%s]\n" \
            "-u, --uri=URI              use the context with the provided URI\n" \
            "-h, --help                 prints this message\n",
            "",// pidFile,
            ""//configFile,
        );
    }
}

/**************************************************************************
 *    Function: Print Usage
 *    Description:
 *        Output the command-line options for this daemon.
 *    Params:
 *        @argc - Standard argument count
 *        @argv - Standard argument array
 *    Returns:
 *        returns void always
 **************************************************************************/
char* daemon_version()
{
    static char version[31] = {0};
    snprintf(version, sizeof(version), "%d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
    return version;
}

#define BITS_PER_BYTE 8
#define BITS_PER_TYPE(type) (sizeof(type) * BITS_PER_BYTE)
#define BIT_MASK(nr)    (nr == BITS_PER_TYPE(1ULL) ? ~0ULL : ((1ULL << nr) - 1))

static inline float print1byte(uint8_t input, const struct iio_data_format *fmt)
{
    input >>= fmt->shift;
    input &= BIT_MASK(fmt->bits);

    float value = 0.0;

    if(fmt->is_signed) {
        int8_t val = (int8_t)(input << (8 - fmt->bits)) >> (8 - fmt->bits);
        value = (float)val;
    } else {
        value = (float)input;
    }

    if(fmt->with_scale)
        value *= fmt->scale;

    return value;
}

static inline float print2byte(uint16_t input, const struct iio_data_format *fmt)
{
    /* First swap if incorrect endian */
    if (fmt->is_be)
        input = be16toh(input);
    else
        input = le16toh(input);

    input >>= fmt->shift;
    input &= BIT_MASK(fmt->bits);

    float value = 0.0;

    if (fmt->is_signed) {
        int16_t val = (int16_t)(input << (16 - fmt->bits)) >> (16 - fmt->bits);
        value = (float)val;
    } else {
        value = (float)input;
    }

    if(fmt->with_scale)
        value *= fmt->scale;

    return value;
}

static inline float print4byte(uint32_t input, const struct iio_data_format *fmt)
{
    /* First swap if incorrect endian */
    if (fmt->is_be)
        input = be32toh(input);
    else
        input = le32toh(input);

    input >>= fmt->shift;
    input &= BIT_MASK(fmt->bits);

    float value = 0.0;

    if (fmt->is_signed) {
        int32_t val = (int32_t)(input << (32 - fmt->bits)) >>
        (32 - fmt->bits);
        value = (float)val;
    } else {
        value = (float)input;
    }

    if(fmt->with_scale)
        value *= fmt->scale;

    return value;
}

static inline float print8byte(uint64_t input, const struct iio_data_format *fmt)
{
    /* First swap if incorrect endian */
    if (fmt->is_be)
        input = be64toh(input);
    else
        input = le64toh(input);

    input >>= fmt->shift;
    input &= BIT_MASK(fmt->bits);

    float value = 0.0;

    if (fmt->is_signed) {
        int64_t val = (int64_t)(input << (64 - fmt->bits)) >>
        (64 - fmt->bits);
        value = (float)val;
    } else {
        value = (float)input;
    }

    return value;
}

static inline int64_t print_timestamp(uint64_t input, const struct iio_data_format *fmt)
{
    /* First swap if incorrect endian */
    if (fmt->is_be)
        input = be64toh(input);
    else
        input = le64toh(input);

    input >>= fmt->shift;
    input &= BIT_MASK(fmt->bits);

    int64_t value = (int64_t)input;

    return value;
}


static int chan_index;
static int chan_number;
static int bytes_per_cycle;

#define BITS_PER_BYTE 8
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define BITS_TO_BYTES(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE)

// [be|le]:[s|u]bits/storagebitsXrepeat[>>shift]
static inline void print_sample(const struct iio_device *dev, void* buffer, size_t length)
{
    size_t len = length;
    char *ptr = buffer, *start = ptr;

    do {
        struct iio_channel* channel = iio_device_get_channel(dev, chan_index);
        const struct iio_data_format* fmt = iio_channel_get_data_format(channel);

        int bytes = BITS_TO_BYTES(fmt->length);
        float value = 0.0;
        int64_t timestamp = 0;

        if(bytes) {
            if ((ptr - start) % bytes) {
                uint8_t offset = bytes - ((ptr - start) % bytes);
                ptr += offset;
                len -= offset;
                bytes_per_cycle += offset;
            }
        }

        switch(bytes) {
            case 1:
                value = print1byte(*(uint8_t *)ptr, fmt);
                break;
            case 2:
                value = print2byte(*(uint16_t *)ptr, fmt);
                break;
            case 4:
                value = print4byte(*(uint32_t *)ptr, fmt);
                break;
            case 8:
                if(fmt->with_scale == false)
                    timestamp = print_timestamp(*(uint64_t *)ptr, fmt);
                else
                    value = print8byte(*(uint64_t *)ptr, fmt);
                break;
            default:
                break;
        };

        ptr += bytes;
        len -= bytes;
        bytes_per_cycle += bytes;

        if(fmt->with_scale == false)
            debug_printf_n("len=%d process %s channel [%d] : %" PRId64, len, iio_channel_get_id(channel), bytes, timestamp);
        else
            debug_printf_n("len=%d process %s channel [%d] : %05f", len, iio_channel_get_id(channel), bytes, value);

        if(++chan_index == chan_number)
        {
            debug_printf_n("cycle [%d==%d] bytes=%d", chan_index, chan_number, bytes_per_cycle);
            bytes_per_cycle = 0;
            chan_index = 0;
        }
    } while(len > 0);
}

int loop(struct iio_buffer* buffer)
{
    int errsv = 0;

    int ret = iio_buffer_set_blocking_mode(buffer, true);
    const struct iio_device *dev = iio_buffer_get_device(buffer);
    size_t sample_size = iio_device_get_sample_size(dev);

    while(!shutdown_flag) {
        ret = iio_buffer_refill(buffer);

        if(ret < 0) {
            char buf[256];
            iio_strerror(-ret, buf, sizeof(buf));
            fprintf(stderr, "Unable to refill buffer: %s\n", buf);
            break;
        }

        if (iio_buffer_step(buffer) == sample_size) {
            syslog(LOG_DEBUG, "iio_buffer_step(buffer) == sample_size : %d == %d", iio_buffer_step(buffer), sample_size);
            void *start = iio_buffer_start(buffer);
            size_t len = (intptr_t) iio_buffer_end(buffer) - (intptr_t) start;
            print_sample(dev, start, len);
        } else {
            syslog(LOG_DEBUG, "iio_buffer_step(buffer) != sample_size");

        }

        {
            struct signalfd_siginfo fdsi = {0};
            ssize_t len;
            len = read(sigfd, &fdsi, sizeof(struct signalfd_siginfo));
            errsv = errno;

            if (len != sizeof(struct signalfd_siginfo)) {
                if(errsv == EAGAIN) continue;
                syslog(LOG_CRIT, "reading sigfd failed");
            }

            switch(fdsi.ssi_signo)
            {
                case SIGINT:
                case SIGTERM:
                    syslog(LOG_DEBUG, "SIGTERM or SIGINT signal recieved - shutting down...");
                    shutdown_flag = 1;
                    break;
                case SIGHUP:
                    hup_flag = 1;
                    break;
                default:
                    break;
            }
        }
    }

    return 0;
}

int loop_local(struct iio_buffer* buffer)
{
    int epollfd = 0;
    int errsv = 0;

    int ret = iio_buffer_set_blocking_mode(buffer, false);
    int fd = iio_buffer_get_poll_fd(buffer);
    errsv = -fd;

    if(fd < 0)
    {
        syslog(LOG_CRIT, "iio_buffer_get_poll_fd : failed with [%d] : %s", errsv, strerror(errsv));
        goto fail;
    }

    const struct iio_device *dev = iio_buffer_get_device(buffer);

    size_t sample_size = iio_device_get_sample_size(dev);

    epollfd = epoll_create1(0);

    struct epoll_event event = {0};

    event.events = EPOLLIN | EPOLLET;
    event.data.fd = fd;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
        errsv = errno;
        syslog(LOG_CRIT, "epoll_ctl : iiofd failed with [%d] : %s", errsv, strerror(errsv));
        goto fail;
    }

    struct epoll_event events[1];

    while(!shutdown_flag) {
        int nfds = epoll_wait(epollfd, events, 1, -1); // timeout in milliseconds
        errsv = errno;

        if (nfds == -1) {
            syslog(LOG_CRIT, "epoll_wait failed with [%d] : %s", errsv, strerror(errsv));
            break;
        }

        ret = iio_buffer_refill(buffer);

        if(ret < 0) {
            char buf[256];
            iio_strerror(-ret, buf, sizeof(buf));
            fprintf(stderr, "Unable to refill buffer: %s\n", buf);
            break;
        }

        if (iio_buffer_step(buffer) == sample_size) {
            syslog(LOG_DEBUG, "iio_buffer_step(buffer) == sample_size");
        } else {
            syslog(LOG_DEBUG, "iio_buffer_step(buffer) != sample_size");
        }
    }

    return 0;

    fail:
    errno = errsv;
    return -1;
}

/**************************************************************************
 *    Function: main
 *    Description:
 *        The c standard 'main' entry point function.
 *    Params:
 *        @argc - count of command line arguments given on command line
 *        @argv - array of arguments given on command line
 *    Returns:
 *        returns integer which is passed back to the parent process
 **************************************************************************/
int main(int argc, char ** argv)
{
    int daemon_flag = 1; //daemonizing by default
    int c = -1;
    int option_index = 0;

    int errsv = 0;
    int ret = 0;

    char* uri = "";

    while((c = getopt_long(argc, argv, "Vvl:nkHp:c:u:h", long_options, &option_index)) != -1) {
        switch(c) {
            case 'v' :
                printf("%s", daemon_version());
                exit(EXIT_SUCCESS);
                break;
            case 'V' :
                verbose_flag = 1;
                break;
            case 'l':
                log_level = strtol(optarg, 0, 10);
                break;
            case 'n' :
                printf("Not daemonizing!\n");
                daemon_flag = 0;
                break;
            case 'k' :
                kill_flag = 1;
                break;
            case 'H' :
                hup_flag = 1;
                break;
            case 'p' :
                pidFile = optarg;
                break;
            case 'c':
                //configFile = optarg;
                //printf("Using config file: %s\n", configFile);
                break;
            case 'u':
                uri = optarg;
                printf("Using URI: %s\n", uri);
                break;
            case 'h':
                PrintUsage(argc, argv);
                exit(EXIT_SUCCESS);
                break;
            default:
                break;
        }
    }

    pid_t pid = read_pid_file(pidFile);
    errsv = errno;

    if(pid > 0) {
        ret = kill(pid, 0);
        if(ret == -1) {
            fprintf(stderr, "%s : %s pid file exists, but the process doesn't!\n", PACKAGE_NAME, pidFile);

            if(kill_flag || hup_flag)
                goto quit;

            unlink(pidFile);
        } else {
            /** check if -k (kill) passed*/
            if(kill_flag)
            {
                kill(pid, SIGTERM);
                goto quit;
            }

            /** check if -h (hup) passed*/
            if(hup_flag)
            {
                kill(pid, SIGHUP);
                goto quit;
            }
        }
    }

    if(daemon_flag) {
        daemonize("/", 0);
        pid = create_pid_file(pidFile);
    } else
        openlog(PACKAGE_NAME, LOG_PERROR, LOG_DAEMON);

    /** setup signals */
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGQUIT);
    sigaddset(&mask, SIGHUP);
    sigaddset(&mask, SIGPIPE);
    sigaddset(&mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) == -1) {
        syslog(LOG_ERR, "Could not register signal handlers (%s).", strerror(errno));
        goto unlink_pid;
    }

    sigfd = signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK);

    /** set log level */
    setlogmask(LOG_UPTO(log_level));

    static struct iio_context *ctx;
    static struct iio_buffer *buffer;
    struct iio_device *dev;
    unsigned nb_channels;
    unsigned int buffer_size = SAMPLES_PER_READ;

    ctx = iio_create_context_from_uri(uri);
    if(ctx == 0)
    {
        syslog(LOG_CRIT, "Failed to create contex from uri: %s", uri);
        goto fail;
    }

    dev = iio_context_find_device(ctx, argv[optind]);
    if(dev == 0)
    {
        syslog(LOG_CRIT, "Device not found: %s", argv[optind]);
        goto fail_free_contex;
    }

    chan_number = nb_channels = iio_device_get_channels_count(dev);
    fprintf(stderr, "%u channels found:\n", nb_channels);

    for (int i = 0; i < nb_channels; i++) {
        struct iio_channel* channel = iio_device_get_channel(dev, i);
        if(channel == 0) {
            fprintf(stderr, "failed getting channel %d\n", i);
            goto fail_free_contex;
        }

        iio_channel_enable(channel);
        const char* channel_name = iio_channel_get_id(channel);
        fprintf(stderr, "enabled channel %s\n", channel_name);
    }

    buffer = iio_device_create_buffer(dev, buffer_size, false);
    if (!buffer) {
        char buf[256];
        iio_strerror(errno, buf, sizeof(buf));
        fprintf(stderr, "Unable to allocate buffer: %s\n", buf);
        iio_context_destroy(ctx);
        return EXIT_FAILURE;
    }

    ret = loop(buffer);

    // cleanup:
    unlink_pid:
    unlink(pidFile);

    quit:
    return 0;

    fail_free_contex:
    iio_context_destroy(ctx);

    fail:
    return -1;
}
