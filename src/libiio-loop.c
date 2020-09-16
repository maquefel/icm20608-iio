#include "libiio-loop.h"

#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>

#include <signal.h>
#include <sys/signalfd.h>

#include <iio.h>

#include "iio_grab.h"

#define SAMPLES_PER_READ 1
extern int sigfd;

ssize_t print_sample(const struct iio_channel *chn, void *buffer, size_t bytes, __notused void *d)
{
    const struct iio_data_format *fmt = iio_channel_get_data_format(chn);

    float value = 0.0;
    int64_t timestamp = 0;

    switch(bytes) {
        case 1:
            value = b8tof(*(uint8_t *)buffer, fmt->is_be, fmt->is_signed, fmt->shift, fmt->length);
            break;
        case 2:
            value = b16tof(*(uint16_t *)buffer, fmt->is_be, fmt->is_signed, fmt->shift, fmt->length);
            break;
        case 4:
            value = b32tof(*(uint32_t *)buffer, fmt->is_be, fmt->is_signed, fmt->shift, fmt->length);
            break;
        case 8:
            if(fmt->with_scale == false)
                timestamp = get_timestamp(*(uint64_t *)buffer, fmt->is_be, fmt->shift, fmt->length);
            else
                value = b64tof(*(uint64_t *)buffer, fmt->is_be, fmt->is_signed, fmt->shift, fmt->length);
            break;
        default:
            break;
    };

    if(fmt->with_scale) {
        value *= fmt->scale;
        fprintf(stdout, "%s : %05f\n", iio_channel_get_id(chn), value);
    } else
        fprintf(stdout, "%s : %" PRId64 "\n", iio_channel_get_id(chn), timestamp);

    return bytes;
}

int libiio_loop(const char* uri, const char* device)
{
    int errsv = 0;
    int shutdown_flag = 0;

    struct iio_context *ctx;
    struct iio_buffer *buffer;

    struct iio_device *dev;

    unsigned nb_channels;
    unsigned int buffer_size = SAMPLES_PER_READ;

    int ret = -1;

    ctx = iio_create_context_from_uri(uri);
    if(ctx == 0)
    {
        errsv = errno;
        fprintf(stderr, "Failed to create contex from uri %s with %d:%s", uri, errsv, strerror(errsv));
        goto fail;
    }

    dev = iio_context_find_device(ctx, device);
    if(dev == 0)
    {
        errsv = EINVAL;
        fprintf(stderr, "Device not found: %s", device);
        goto fail_free_contex;
    }

    nb_channels = iio_device_get_channels_count(dev);
    fprintf(stdout, "%u channels found", nb_channels);

    for (int i = 0; i < nb_channels; i++) {
        struct iio_channel* channel = iio_device_get_channel(dev, i);
        if(channel == 0) {
            fprintf(stderr, "failed getting channel %d\n", i);
            goto fail_free_contex;
        }

        iio_channel_enable(channel);
        const char* channel_name = iio_channel_get_id(channel);
        fprintf(stdout, "enabled channel %s\n", channel_name);
    }

    buffer = iio_device_create_buffer(dev, buffer_size, false);
    if (!buffer) {
        char err_str[1024];
        iio_strerror(errno, err_str, sizeof(err_str));
        fprintf(stderr, "Unable to allocate buffer: %s\n", err_str);
        goto fail_free_contex;
    }

    iio_buffer_set_blocking_mode(buffer, true);

    while(!shutdown_flag) {
        ret = iio_buffer_refill(buffer);

        if(ret < 0) {
            char err_str[1024];
            iio_strerror(-ret, err_str, sizeof(err_str));
            fprintf(stderr, "Unable to refill buffer: %s\n", err_str);
            break;
        }

        ret = iio_buffer_foreach_sample(buffer, print_sample, NULL);
        if (ret < 0) {
            char err_str[1024];
            iio_strerror(-ret, err_str, sizeof(err_str));
            fprintf(stderr, "%s (%d) while processing buffer\n", err_str, ret);
        }

        {
            struct signalfd_siginfo fdsi = {0};
            ssize_t len;
            len = read(sigfd, &fdsi, sizeof(struct signalfd_siginfo));
            errsv = errno;

            if (len != sizeof(struct signalfd_siginfo)) {
                if(errsv == EAGAIN) continue;
                fprintf(stderr, "reading sigfd failed");
            }

            switch(fdsi.ssi_signo)
            {
                case SIGINT:
                case SIGTERM:
                    fprintf(stderr, "SIGTERM or SIGINT signal recieved - shutting down...");
                    shutdown_flag = 1;
                    break;
                case SIGHUP:
                    break;
                default:
                    break;
            }
        }
    }

    ret = 0;

    iio_buffer_destroy(buffer);

    fail_free_contex:
    iio_context_destroy(ctx);

    fail:
    errno = errsv;
    return ret;
}
