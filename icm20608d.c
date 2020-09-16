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
#include "libiio-loop.h"
#include "local-loop.h"

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

/** signal fd */
int sigfd;

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

static struct option long_options[] =
{
    {"verbose",         no_argument,        &verbose_flag,      'V'},
    {"version",         no_argument,        0,                  'v'},
    {"log-level",       required_argument,  0,                  'l'},
    {"n",               no_argument,        &no_daemon_flag,    'n'},
    {"kill",            no_argument,        &kill_flag,         'k'},
    {"hup",             no_argument,        &hup_flag,          'H'},
    {"pid",             required_argument,  0,                  'p'},
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
            "./icm20608d [-u ip:<IP>] icm20608"
            "-v, --version              prints version and exits\n" \
            "-V, --verbose              be more verbose\n" \
            "-l, --log-level            set log level[default=LOG_INFO]\n" \
            "-n                         don\'t fork off as daemon\n" \
            "-k, --kill                 kill old daemon instance in case if present\n" \
            "-H, --hup                  send daemon signal to reload configuration\n" \
            "-p, --pid                  path to pid file[default=%s]\n" \
            "-u, --uri=URI              use the context with the provided URI\n" \
            "-h, --help                 prints this message\n",
            pidFile
        );
    }
}

/**************************************************************************
 *    Function: Print daemon version
 *    Description:
 *        Output the command-line options for this daemon.
 *    Params:
 *    Returns:
 *        returns string with version
 **************************************************************************/
char* daemon_version()
{
    static char version[31] = {0};
    snprintf(version, sizeof(version), "%d.%d.%d\n", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH);
    return version;
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
    char* device = "";

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

    if(optind < argc)
        device = argv[optind];

    if(device == 0)
        fprintf(stderr, "please provide me with correct device");

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

    if(uri == 0)
        ret = local_loop(device);
    else
        ret = libiio_loop(uri, "icm20608");

    // cleanup:
    unlink_pid:
    unlink(pidFile);

    quit:
    return 0;
}
