/******************************************************************************
 *
 * Copyright (c) 2014, Intel Corporation.

 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59
 * Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *******************************************************************************/

/*******************************************************************************
 **
 ** Name:           bluetooth_rfkill_event.c
 **
 ** Description:    This program is listening rfkill event and detect when a
 **                 'power' rfkill interface is unblocked and trigger FW patch
 **                 download for detected chip.
 **
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <ctype.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <limits.h>
#include <getopt.h>
#include <syslog.h>
#include <stdarg.h>
#include <glib.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>


enum rfkill_switch_type {
    BT_PWR,
    BT_HCI,
};

/* list of all supported chips:
   name is defined in the kernel driver implementing rfkill interface for power */
#define BCM_RFKILL_NAME "bcm43xx Bluetooth\n"
#define BCM_43341_UART_DEV "/dev/ttyMFD0"
#define BD_ADD_FACTORY_FILE "/factory/bluetooth_address"
char factory_bd_add[18];
const char default_bd_addr[] = "00:43:34:b1:be:ef";

#define DEFAULT_CONFIG_FILE "/etc/firmware/bcm43341.conf"

/* attempt to set hci dev UP */
#define MAX_RETRY 10

enum rfkill_operation {
    RFKILL_OP_ADD = 0,
    RFKILL_OP_DEL,
    RFKILL_OP_CHANGE,
    RFKILL_OP_CHANGE_ALL,
};

enum rfkill_type {
    RFKILL_TYPE_ALL = 0,
    RFKILL_TYPE_WLAN,
    RFKILL_TYPE_BLUETOOTH,
    RFKILL_TYPE_UWB,
    RFKILL_TYPE_WIMAX,
    RFKILL_TYPE_WWAN,
    RFKILL_TYPE_GPS,
    RFKILL_TYPE_FM,
    NUM_RFKILL_TYPES,
};

struct rfkill_event {
    unsigned int  idx;
    unsigned char type;
    unsigned char op;
    unsigned char soft, hard;
} __packed;

struct rfkill_switch {
    gchar *name;
    enum rfkill_switch_type type;
    union {
	struct {
	    int dev_id;
	} hci;
    };
};

/* HCI UART driver initialization utility; usually it takes care of FW patch download as well */
char hciattach[PATH_MAX];
char hciattach_options[PATH_MAX];
char hci_uart_default_dev[PATH_MAX] = BCM_43341_UART_DEV;

gboolean hci_dev_registered;
char *config_file = DEFAULT_CONFIG_FILE;
GHashTable *switch_hash = NULL; /* hash index to metadata about the switch */

struct main_opts {
    /* 'fork' will keep running in background the hciattach utility; N/A if enable_hci is FALSE */
    gboolean    enable_fork;
    /* send enable Low Power Mode to Broadcom bluetooth controller; needed if power driver implements it */
    gboolean    enable_lpm;
    /* register the hci device */
    gboolean    enable_hci;
    /* set UART baud rate */
    gboolean    set_baud_rate;
    int         baud_rate;
    /* download FW patch */
    gboolean    dl_patch;
    char*       fw_patch;
    /* UART device used for bluetooth; platform dependant */
    char*       uart_dev;
    /* configure BD address */
    gboolean    set_bd;
    char*       bd_add;
    /* set SCO routing for audio interface */
    gboolean    set_scopcm;
    char*       scopcm;
    /* Delay before patchram download (microseconds) */
    guint       tosleep;
};

struct main_opts main_opts;

static const char * const supported_options[] = {
    "fork",
    "lpm",
    "reg_hci",
    "baud_rate",
    "fw_patch",
    "uart_dev",
    "scopcm",
    "tosleep"
};

static int log_debug = 0;
static int log_stderr = 0;

static void bt_log(int level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));

static void bt_log(int level, const char *format, ...)
{
    static int log_open = 0;
    va_list ap;

    if (level == LOG_DEBUG && !log_debug)
        return;

    if (!log_open) {
        openlog("bluetooth_rfkill_event",
                (log_stderr ? LOG_PERROR : 0) | LOG_PID,
                LOG_DAEMON);
        log_open = 1;
    }

    va_start(ap, format);
    vsyslog(level, format, ap);
    va_end(ap);
}

#define DEBUG(fmt, args...) do {                        \
        bt_log(LOG_DEBUG, "%s(%s:%d): " fmt "\n",       \
            __FUNCTION__, __FILE__, __LINE__, ## args); \
    } while (0)

#define INFO(fmt, args...) do {                         \
        bt_log(LOG_INFO, "%s(%s:%d): " fmt "\n",        \
            __FUNCTION__, __FILE__, __LINE__, ## args); \
    } while (0)

#define WARN(fmt, args...) do {                         \
        bt_log(LOG_WARNING, "%s(%s:%d): " fmt "\n",     \
            __FUNCTION__, __FILE__, __LINE__, ## args); \
    } while (0)

#define ERROR(fmt, args...) do {                        \
        bt_log(LOG_ERR, "%s(%s:%d): " fmt "\n",         \
            __FUNCTION__, __FILE__, __LINE__, ## args); \
    } while (0)

#define FATAL(fmt, args...) do {                        \
        bt_log(LOG_ERR, "%s(%s:%d): " fmt "\n",         \
            __FUNCTION__, __FILE__, __LINE__, ## args); \
        exit(EXIT_FAILURE);                             \
    } while (0)

static void switch_free(gpointer data)
{
    struct rfkill_switch *s = data;
    g_free(s->name);
    g_free(s);
}

static const char *op2string(enum rfkill_operation op)
{
    switch (op) {
    case RFKILL_OP_ADD: return "ADD";
    case RFKILL_OP_DEL: return "DEL";
    case RFKILL_OP_CHANGE: return "CHANGE";
    case RFKILL_OP_CHANGE_ALL: return "CHANGE_ALL";
    default: return NULL;
    }
}

static const char *type2string(enum rfkill_type type)
{
    switch(type) {
    case RFKILL_TYPE_ALL: return "ALL";
    case RFKILL_TYPE_WLAN: return "WLAN";
    case RFKILL_TYPE_BLUETOOTH: return "BLUETOOTH";
    case RFKILL_TYPE_UWB: return "UWB";
    case RFKILL_TYPE_WIMAX: return "WIMAX";
    case RFKILL_TYPE_WWAN: return "WWAN";
    case RFKILL_TYPE_GPS: return "GPS";
    case RFKILL_TYPE_FM: return "FM";
    default: return NULL;
    }
}

void init_config()
{
    memset(&main_opts, 0, sizeof(main_opts));

    main_opts.enable_fork = TRUE;
    main_opts.enable_lpm = TRUE;
    main_opts.enable_hci = FALSE;
    main_opts.set_baud_rate = FALSE;
    main_opts.dl_patch = FALSE;
    main_opts.set_bd = FALSE;
    main_opts.set_scopcm = FALSE;
    main_opts.tosleep = 0;
}

GKeyFile *load_config(const char *file)
{
    GError *err = NULL;
    GKeyFile *keyfile;

    keyfile = g_key_file_new();

    g_key_file_set_list_separator(keyfile, ',');

    if (!g_key_file_load_from_file(keyfile, file, 0, &err)) {
        if (!g_error_matches(err, G_FILE_ERROR, G_FILE_ERROR_NOENT))
            FATAL("Parsing %s failed: %s", file, err->message);
        g_error_free(err);
        g_key_file_free(keyfile);
        return NULL;
    }

    return keyfile;
}

void check_config(GKeyFile *config)
{
    char **keys;
    int i;

    if (!config)
        return;

    keys = g_key_file_get_groups(config, NULL);

    for (i = 0; keys != NULL && keys[i] != NULL; i++) {
        if (!g_str_equal(keys[i], "General"))
            WARN("Unknown group %s in main.conf", keys[i]);
    }

    g_strfreev(keys);

    keys = g_key_file_get_keys(config, "General", NULL, NULL);

    for (i = 0; keys != NULL && keys[i] != NULL; i++) {
        gboolean found;
        unsigned int j;

        found = FALSE;
        for (j = 0; j < G_N_ELEMENTS(supported_options); j++) {
            if (g_str_equal(keys[i], supported_options[j])) {
                found = TRUE;
                break;
            }
        }

        if (!found)
            WARN("Unknown key %s in main.conf", keys[i]);
    }

    g_strfreev(keys);
}

void parse_config(GKeyFile *config)
{
    GError *err = NULL;
    char *str;
    int val;
    gboolean boolean;

    if (!config)
        return;

    check_config(config);

    boolean = g_key_file_get_boolean(config, "General", "fork", &err);
    if (err) {
        g_clear_error(&err);
    } else
        main_opts.enable_fork = boolean;

    boolean = g_key_file_get_boolean(config, "General", "lpm", &err);
    if (err) {
        g_clear_error(&err);
    } else
        main_opts.enable_lpm = boolean;

    boolean = g_key_file_get_boolean(config, "General", "reg_hci", &err);
    if (err) {
        g_clear_error(&err);
    } else
        main_opts.enable_hci = boolean;

    val = g_key_file_get_integer(config, "General", "baud_rate", &err);
    if (err) {
        g_clear_error(&err);
    } else {
        main_opts.baud_rate = val;
        main_opts.set_baud_rate = TRUE;
    }

    str = g_key_file_get_string(config, "General", "fw_patch", &err);
    if (err) {
        g_clear_error(&err);
    } else {
        g_free(main_opts.fw_patch);
        main_opts.fw_patch = str;
        main_opts.dl_patch = TRUE;
    }

    str = g_key_file_get_string(config, "General", "uart_dev", &err);
    if (err) {
        g_clear_error(&err);
        main_opts.uart_dev = hci_uart_default_dev;
    } else {
        g_free(main_opts.uart_dev);
        main_opts.uart_dev = str;
    }

    str = g_key_file_get_string(config, "General", "scopcm", &err);
    if (err) {
        g_clear_error(&err);
    } else {
        g_free(main_opts.scopcm);
        main_opts.scopcm = str;
        main_opts.set_scopcm = TRUE;
    }

    val = g_key_file_get_integer(config, "General", "tosleep", &err);
    if (err) {
        g_clear_error(&err);
    } else {
        main_opts.tosleep = val;
    }

}

gboolean check_bd_format(const char* bd_add)
{
    int i, len;

    len = strlen(bd_add);

    if (len != 17)
        return FALSE;

    for (i = 0 ; i < len; i++)
    {
        /* check that format is xx:xx: ... etc. */
        if ((isxdigit(bd_add[i]) && i%3 != 2) ||
            (bd_add[i] == ':' && i%3 == 2))
        {
            ;
        }
        else
        {
            return FALSE;
        }
    }

    return TRUE;
}

void load_bd_add(void)
{
    FILE *fp;
    int ret;

    fp = fopen(BD_ADD_FACTORY_FILE, "r");

    /* if BD add file has not been provisioned use default one */
    if (fp == NULL)
    {
        memcpy(factory_bd_add, default_bd_addr, sizeof(factory_bd_add));
        main_opts.bd_add = factory_bd_add;
        main_opts.set_bd = TRUE;
        return;
    }

    ret = fscanf(fp, "%17c", factory_bd_add);

    /* if factory BD address is not well formatted or not present use default one*/
    if (!(ret == 1 && check_bd_format(factory_bd_add)))
    {
        memcpy(factory_bd_add, default_bd_addr, sizeof(factory_bd_add));
    }
    main_opts.bd_add = factory_bd_add;
    main_opts.set_bd = TRUE;

    fclose(fp);

}

void read_config(char* file)
{
    GKeyFile *config;
    char *cur = hciattach_options;
    const char *end = hciattach_options + sizeof(hciattach_options);

    /* set first default values and then load configured ones */
    init_config();
    config = load_config(file);
    parse_config(config);
    load_bd_add();

    /* set always configured options: use same configured baud-rate also for download, and ignore first 2 bytes (needed by bcm43341 and more recent brcm bt chip) */
    cur += snprintf(cur, end-cur, "%s", "--use_baudrate_for_download --no2bytes");

    /* concatenate configured options */
    if ((cur < end) && (main_opts.enable_fork)) {
        cur += snprintf(cur, end-cur," %s", "--enable_fork");
    }
    if ((cur < end) && (main_opts.enable_lpm)) {
        cur += snprintf(cur, end-cur," %s", "--enable_lpm");
    }
    if ((cur < end) && (main_opts.enable_hci)) {
        cur += snprintf(cur, end-cur," %s", "--enable_hci");
    }
    if ((cur < end) && (main_opts.set_baud_rate)) {
        cur += snprintf(cur, end-cur," --baudrate %d", main_opts.baud_rate);
    }
    if ((cur < end) && (main_opts.dl_patch)) {
        cur += snprintf(cur, end-cur," --patchram %s", main_opts.fw_patch);
    }
    if ((cur < end) && (main_opts.set_bd)) {
        cur += snprintf(cur, end-cur," --bd_addr %s", main_opts.bd_add);
    }
    if ((cur < end) && (main_opts.set_scopcm)) {
        cur += snprintf(cur, end-cur," --scopcm %s", main_opts.scopcm);
    }
    if ((cur < end) && (main_opts.tosleep)) {
        cur += snprintf(cur, end-cur," --tosleep %d", main_opts.tosleep);
    }
    if ((cur < end) && log_debug) {
        cur += snprintf(cur, end-cur," -d");
    }
}

void free_hci()
{
    char cmd[PATH_MAX];
    int r;

    DEBUG("");

    snprintf(cmd, sizeof(cmd), "pidof %s", hciattach);

    r = system(cmd);
    if (WIFEXITED(r) && !WEXITSTATUS(r)) {
        snprintf(cmd, sizeof(cmd), "killall --wait %s", hciattach);
        r = system(cmd);
        INFO("killing %s %s", hciattach,
             (WIFEXITED(r) && !WEXITSTATUS(r)) ? "succeeded" : "failed");
    } else {
        INFO("No %s process to be found", hciattach);
    }
}

void attach_hci()
{
    char hci_execute[PATH_MAX];
    int r;

    DEBUG("");

    snprintf(hci_execute, sizeof(hci_execute), "%s %s %s", hciattach, hciattach_options, main_opts.uart_dev);

    r = system(hci_execute);
    INFO("executing %s %s", hci_execute,
         (WIFEXITED(r) && !WEXITSTATUS(r)) ? "succeeded" : "failed");

    /* remember if hci device has been registered (in case conf file is changed) */
    hci_dev_registered = main_opts.enable_hci;
}

void up_hci(int hci_idx)
{
    int sk, i;
    struct hci_dev_info hci_info;

    DEBUG("");

    sk = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);

    if (sk < 0)
    {
        ERROR("Failed to create bluetooth hci socket (%s/%d)",
              strerror(errno), errno);
        return;
    }

    memset(&hci_info, 0, sizeof(hci_info));

    hci_info.dev_id = hci_idx;

    for (i = 0;  i < MAX_RETRY; i++)
    {
        if (ioctl(sk, HCIGETDEVINFO, (void *) &hci_info) < 0)
        {
            ERROR("Failed to get HCI device information (%s/%d)",
                  strerror(errno), errno);
            /* sleep 100ms */
            usleep(100*1000);
            continue;
        }

        if (hci_test_bit(HCI_RUNNING, &hci_info.flags) && !hci_test_bit(HCI_INIT, &hci_info.flags))
        {
            /* check if kernel has already set device UP... */
            if (!hci_test_bit(HCI_UP, &hci_info.flags))
            {
                if (ioctl(sk, HCIDEVUP, hci_idx) < 0)
                {
                    /* ignore if device is already UP and ready */
                    if (errno == EALREADY)
                        break;

                    ERROR("Failed to set hci device UP (%s/%d)",
                          strerror(errno), errno);
                }
            }
            break;
        }

        /* sleep 100ms */
        usleep(100*1000);
    }

    close(sk);
}

/* calling this routine to be sure to have rfkill hci bluetooth interface unblocked:
   if user does:
   - 'rfkill block bluetooth' and then
   - 'rfkill unblock 2'
   once hci bluetooth is registered back it will be blocked */
void rfkill_bluetooth_unblock()
{
    int fd;
    struct rfkill_event event;

    DEBUG("");

    fd = open("/dev/rfkill", O_RDWR | O_CLOEXEC);
    if (fd < 0)
    {
        ERROR("fail to open rfkill interface (%s/%d)",
              strerror(errno), errno);
        return;
    }
    memset(&event, 0, sizeof(event));
    event.op = RFKILL_OP_CHANGE_ALL;
    event.type = RFKILL_TYPE_BLUETOOTH;
    event.soft = 0;
    if (write(fd, &event, sizeof(event)) < 0)
    {
        ERROR("fail to unblock rfkill bluetooth (%s/%d)",
              strerror(errno), errno);
    }
    close(fd);

}

static int rfkill_switch_add(struct rfkill_event *event)
{
    char sysname[PATH_MAX];
    struct rfkill_switch *s = NULL;
    int fd_name = -1;
    int r = -1;
    int type;

    DEBUG("");

    /* get the name to check the bt chip */
    snprintf(sysname, sizeof(sysname), "/sys/class/rfkill/rfkill%u/name",
	     event->idx);

    fd_name = open(sysname, O_RDONLY);
    if (fd_name < 0) {
	ERROR("Failed to open rfkill name (%s/%d)", strerror(errno), errno);
	goto out;
    }

    /* read name */
    memset(sysname, 0, sizeof(sysname));
    if (read(fd_name, sysname, sizeof(sysname) - 1) < 0) {
	ERROR("Failed to read rfkill name (%s/%d)", strerror(errno), errno);
	goto out;
    }

    /* based on chip read its config file, if any, and define the hciattach utility used to dowload the patch */
    if (!strncmp(BCM_RFKILL_NAME, sysname, sizeof(BCM_RFKILL_NAME))) {
	read_config(config_file);
	snprintf(hciattach, sizeof(hciattach), "brcm_patchram_plus");
	type = BT_PWR;
    } else if (g_str_has_prefix(sysname, "hci")) {
	type = BT_HCI;
    } else {
	DEBUG("Skipping over unsupported rfkill switch '%s'", sysname);
	goto out;
    }

    DEBUG("Recording rfkill switch %d into hash", event->idx);
    s = g_new0(struct rfkill_switch, 1);
    s->name = g_strdup(sysname);
    s->type = type;
    if (type == BT_HCI) {
	s->hci.dev_id = atoi(sysname + 3);
    }
    g_hash_table_replace(switch_hash, GINT_TO_POINTER(event->idx), s);

    r = 0;

out:
    if (fd_name >= 0)
	close(fd_name);

    return r;
}

int main(int argc, char **argv)
{
    struct rfkill_event event;
    struct pollfd p;
    ssize_t len;
    int fd, n;
    struct rfkill_switch *s = NULL;

    switch_hash = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL,
					switch_free);

    opterr = 0;
    while (1) {
        static struct option opts[] = {
            { "config", required_argument, NULL, 'c' },
            { "debug", no_argument, NULL, 'd' },
            { "stderr", no_argument, NULL, 's' },
            { 0, 0, 0, 0 }
        };
        int c;

        c = getopt_long(argc, argv, ":c:ds", opts, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            config_file = optarg;
            break;
        case 'd':
            log_debug = 1;
            break;
        case 's':
            log_stderr = 1;
            break;
        case ':':
            FATAL("Option '%s' missing argument", argv[optind-1]);
        default:
            FATAL("Unknown option '%s'", argv[optind-1]);
        }
    }

    INFO("Starting bluetooth_rfkill_event");

    /* this code is ispired by rfkill source code */

    fd = open("/dev/rfkill", O_RDONLY);
    if (fd < 0) {
        FATAL("Can't open RFKILL control device (%s/%d)",
              strerror(errno), errno);
    }

    memset(&p, 0, sizeof(p));
    p.fd = fd;
    p.events = POLLIN | POLLHUP;

    while (1) {
        n = poll(&p, 1, -1);
        if (n < 0) {
            ERROR("Failed to poll RFKILL control device (%s/%d)",
                  strerror(errno), errno);
            break;
        }

        if (n == 0)
            continue;

        len = read(fd, &event, sizeof(event));
        if (len < 0) {
            ERROR("Reading of RFKILL events failed (%s/%d)",
                  strerror(errno), errno);
            break;
        }

        if (len != sizeof(event)) {
            ERROR("Wrong size of RFKILL event (%s/%d)",
                  strerror(errno), errno);
            break;
        }

        /* ignore event for others interfaces (not bluetooth) */
        if (event.type != RFKILL_TYPE_BLUETOOTH)
            continue;

        DEBUG("rfkill event: idx %u type %s(%u) op %s(%u) soft %u hard %u",
              event.idx, type2string(event.type), event.type,
              op2string(event.op), event.op, event.soft, event.hard);

        /* Read rfkill switch metadata on addition; no need to read it
	   repeatedly on every change. */
        if (event.op == RFKILL_OP_ADD)
	    if (rfkill_switch_add(&event) < 0)
		continue;

	s = g_hash_table_lookup(switch_hash, GINT_TO_POINTER(event.idx));
	if (!s) {
	    WARN("Unknown rfkill switch %d", event.idx);
	    continue;
	}

        switch (event.op) {
        case RFKILL_OP_CHANGE:
        case RFKILL_OP_CHANGE_ALL:
        case RFKILL_OP_ADD:
            if (event.soft == 0 && event.hard == 0)
	    {
                if (s->type == BT_PWR)
                {
                    /* if unblock is for power interface: download patch and eventually register hci device */
                    free_hci();
                    attach_hci();
                    /* force to unblock also the bluetooth hci rfkill interface if hci device was registered */
                    if (hci_dev_registered)
                        rfkill_bluetooth_unblock();
                }
                else if (s->type == BT_HCI && hci_dev_registered)
                {
                    /* wait unblock on hci bluetooth interface and force device UP */
                    up_hci(s->hci.dev_id);
                }
            }
            else if (s->type == BT_PWR && hci_dev_registered)
            {
                /* for a block event on power interface force unblock of hci device interface */
                free_hci();
            }

        break;
        case RFKILL_OP_DEL:
            /* in case pwr rfkill interface is removed, unregister hci dev if it was registered */
            if (s->type == BT_PWR && hci_dev_registered)
                free_hci();
	    DEBUG("Removing rfkill switch %d from hash", event.idx);
	    g_hash_table_remove(switch_hash, GINT_TO_POINTER(event.idx));
	    break;

        default:
            continue;
        }

    }

    close(fd);

    return 0;
}
