#include "local-loop.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <math.h>
#include <stdlib.h>
#include <signal.h>

#include <sys/epoll.h>
#include <sys/signalfd.h>

#include "c_bitops.h"
#include "iio_grab.h"

extern int sigfd;

const char* sysfs_iio_devices = "/sys/bus/iio/devices/";

struct iio_device {
    int sysfs_fd; // sysfs directory
    char* device;
};

struct iio_device* find_device(int dirfd, const char* device)
{
    int errsv;
    int ret;

    DIR* dirp = fdopendir(dirfd);
    struct dirent *dp;
    char buff[1024] = {0};

    do {
        errno = 0;
        if ((dp = readdir(dirp)) != NULL) {
            if(dp->d_type == DT_LNK)
            {
                char *d_name;
                asprintf(&d_name, "%s/%s", dp->d_name, "name");

                int fd_name = openat(dirfd, d_name, O_RDONLY);

                if(fd_name == -1)
                {
                    errsv = errno;
                    if(errsv == ENOENT)
                        continue;

                    goto fail;
                }

                ret = read(fd_name, buff, sizeof buff);
                errsv = errno;

                close(fd_name);

                if(ret == -1)
                    goto fail;

                if(strcmp(buff, device) == 0)
                {
                    struct iio_device* dev = malloc(sizeof(struct iio_device));
                    dev->sysfs_fd = openat(dirfd, dp->d_name, O_DIRECTORY);
                    dev->device = strdup(dp->d_name);
                }
            }
        }
    } while (dp != NULL);

    errno = ENODEV;

    fail:
    errno = errsv;
    return 0;
}

int write_channel(int dirfd, const char* name, bool enable)
{
    int ret;
    char* en;

    asprintf(&en, "%s_%s", name, "en");

    int fd = openat(dirfd, en, O_WRONLY);
    if(fd == -1)
        goto fail;

    if(enable)
        ret = write(fd, "1", 1);
    else
        ret = write(fd, "0", 1);

    if(ret == -1)
        goto fail;

    close(fd);

    return 0;

    fail:
    return -1;
}

int enable_channel(int dirfd, const char* name)
{
    return write_channel(dirfd, name, true);
}

int disable_channel(int dirfd, const char* name)
{
    return write_channel(dirfd, name, false);
}

struct imu_channel {
    const char* name;
    unsigned length;    /* [bits] */
    unsigned shift;     /* [bits] */
    unsigned offset;    /* [bytes] */
    double scale;
    bool is_be;
    bool is_signed;
    int scan_index;
};

double in_accel_scale;
double in_anglvel_scale;

unsigned scan_size;

static struct imu_channel channels[] = {
    {"in_accel_x",     16, 0, 0, 1.0f, true,  true, -1},
    {"in_accel_y",     16, 0, 0, 1.0f, true,  true, -1},
    {"in_accel_z",     16, 0, 0, 1.0f, true,  true, -1},
    {"in_anglvel_x",   16, 0, 0, 1.0f, true,  true, -1},
    {"in_anglvel_y",   16, 0, 0, 1.0f, true,  true, -1},
    {"in_anglvel_z",   16, 0, 0, 1.0f, true,  true, -1},
    {"in_timestamp",   64, 0, 0, NAN,  false, true, -1},
    {0, 0, 0, -1},
};

#define IMU_CHANNEL_SIZE (sizeof(channels) - 1)/sizeof(channels[0])

static struct imu_channel* pchannels[IMU_CHANNEL_SIZE];

const char* get_value(int fd, const char* name)
{
    int ret = 0;
    int errsv = 0;
    static char buffer[256];

    int value_fd = openat(fd, name, O_RDONLY);
    errsv = errno;

    if(value_fd == -1)
        goto fail;


    ret = read(value_fd, &buffer, sizeof(buffer));
    errsv = errno;

    if(ret <= 0)
        goto fail_close;

    buffer[ret] = '\0';

    close(value_fd);

    return buffer;

    fail_close:
    close(value_fd);

    fail:
    errno = errsv;
    return 0;
}

double get_double(int dirfd, const char* name)
{
    const char* value = get_value(dirfd, name);
    return strtod(value, 0);
}

int get_index(int dirfd, const char* name)
{
    char* in;

    asprintf(&in, "%s_%s", name, "index");
    const char* value = get_value(dirfd, in);

    return atoi(value);
}

int enable_channels(int dirfd)
{
    int ret;
    int i = -1;

    /** get scales */
    in_accel_scale = get_double(dirfd, "in_accel_scale");
    in_anglvel_scale = get_double(dirfd, "in_anglvel_scale");

    int scan_fd = openat(dirfd, "scan_elements", O_DIRECTORY);

    while(channels[++i].name != 0) {
        /** enable channel */
        ret = enable_channel(scan_fd, channels[i].name);

        /** get and store index */
        int index = get_index(scan_fd, channels[i].name);
        channels[i].scan_index = index;
        pchannels[index] = &channels[i];

        /** assign scale */
        if(strncmp(channels[i].name, "in_accel", strlen("in_accel")) == 0) {
            channels[i].scale = in_accel_scale;
        } else if(strncmp(channels[i].name, "in_anglvel", strlen("in_anglvel")) == 0) {
            channels[i].scale = in_anglvel_scale;
        }
    }

    /** calculate offsets */
    /** calculate offsets */
    unsigned offset = 0;

    for(int i = 0; i < IMU_CHANNEL_SIZE; i++) {
        int bytes = BITS_TO_BYTES(pchannels[i]->length);
        if(offset % bytes)
        {
            offset += (bytes - offset % bytes);
            pchannels[i]->offset = offset;
        } else {
            pchannels[i]->offset = offset;
        }

        offset += BITS_TO_BYTES(pchannels[i]->length);
    }

    scan_size = offset;

    return 0;
}

int sysfs_write_int(int dirfd, const char* name, int value)
{
    int ret = -1;
    int errsv = 0;
    char* val;
    ssize_t val_len = asprintf(&val, "%d", value);

    int fd = openat(dirfd, name, O_WRONLY);
    if(fd == -1)
    {
        errsv = errno;
        goto fail;
    }

    ret = write(fd, val, val_len);
    if(ret == -1) {
        errsv = errno;
        goto fail_close;
    }

    ret = 0;

    fail_close:
    close(fd);

    fail:
    errno = errsv;
    return ret;
}

int enable_buffer(int dirfd)
{
    int ret = 0;

    /** setup length - data samples count */
    ret = sysfs_write_int(dirfd, "buffer/length", 16);
    if(ret == -1)
        goto fail;

    /** enable buffer */
    ret = sysfs_write_int(dirfd, "buffer/enable", 1);

    return ret;

    fail:
    return -1;
}

void cleanup()
{

}

int proccess_samples(const uint8_t* buffer)
{
    for(int i = 0; i < IMU_CHANNEL_SIZE; i++)
    {
        float value = 0.0;
        int64_t timestamp = 0;

        const uint8_t* ptr = buffer + channels[i].offset;

        struct imu_channel* chan = pchannels[i];
        unsigned bytes = BITS_TO_BYTES(chan->length);

        switch(bytes) {
            case 1:
                value = b8tof(*(uint8_t *)ptr, chan->is_be, chan->is_signed, chan->shift, chan->length);
                break;
            case 2:
                value = b16tof(*(uint16_t *)ptr, chan->is_be, chan->is_signed, chan->shift, chan->length);
                break;
            case 4:
                value = b32tof(*(uint32_t *)ptr, chan->is_be, chan->is_signed, chan->shift, chan->length);
                break;
            case 8:
                if(isnan(chan->scale))
                    timestamp = get_timestamp(*(uint64_t *)ptr, chan->is_be, chan->shift, chan->length);
                else
                    value = b64tof(*(uint64_t *)ptr, chan->is_be, chan->is_signed, chan->shift, chan->length);
                break;
            default:
                break;
        };

        if(!isnan(chan->scale)) {
            value *= chan->scale;
            fprintf(stdout, "%s : %05f\n", chan->name, value);
        } else
            fprintf(stdout, "%s : %" PRId64 "\n", chan->name, timestamp);
    }

    return 0;
}

int local_loop(const char* device)
{
    int shutdown_flag = 0;
    int epollfd = 0;
    int errsv = 0;
    int ret;

    /** find device requested */
    /** device => iio:device0 => icm20608 */
    int devices_fd = open(sysfs_iio_devices, O_RDONLY | O_DIRECTORY);
    if(devices_fd == -1) {
        errsv = errno;
        fprintf(stderr, "libiio_loop: open %s failed with %d:%s\n", sysfs_iio_devices, errsv, strerror(errsv));
        goto fail;
    }

    struct iio_device* dev = find_device(devices_fd, device);
    if(dev == 0) {
        errsv = errno;
        fprintf(stderr, "libiio_loop: find device %s in %s failed with %d:%s\n", device, sysfs_iio_devices, errsv, strerror(errsv));
        goto fail;
    }

    /** parse and enable channels */
    ret = enable_channels(dev->sysfs_fd);

    /** enable buffer */
    ret = enable_buffer(dev->sysfs_fd);

    /** open the device */
    int fd = -1;
    {
        char* sdev;
        asprintf(&sdev, "/dev/%s", dev->device);
        fd = open(sdev, O_RDWR);
    }

    epollfd = epoll_create1(0);

    struct epoll_event event = {0};

    event.events = EPOLLIN | EPOLLET;
    event.data.fd = fd;

    if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event) == -1) {
        errsv = errno;
        fprintf(stderr, "epoll_ctl : iiofd failed with [%d] : %s", errsv, strerror(errsv));
        goto fail;
    }

    struct epoll_event events[1];
    uint8_t buffer[1024];

    while(!shutdown_flag) {
        int nfds = epoll_wait(epollfd, events, 1, -1); // timeout in milliseconds
        errsv = errno;

        if (nfds == -1) {
            fprintf(stderr, "epoll_wait failed with [%d] : %s", errsv, strerror(errsv));
            break;
        }

        size_t readen = read(fd, buffer, sizeof buffer);
        if(readen == -1)
            goto fail;

        for (int i = 0; i < readen / scan_size; i++)
            proccess_samples(buffer + scan_size * i);

        {
            struct signalfd_siginfo fdsi = {0};
            ssize_t len;
            len = read(sigfd, &fdsi, sizeof(struct signalfd_siginfo));
            if (len == sizeof(struct signalfd_siginfo))
            {
                switch(fdsi.ssi_signo)
                {
                    case SIGINT:
                    case SIGTERM:
                        fprintf(stderr, "SIGTERM or SIGINT signal recieved - shutting down...\n");
                        shutdown_flag = 1;
                        break;

                    default:
                        break;
                }
            }
        }
    }

    return 0;

    fail:
    errno = errsv;
    return -1;
}
