OBJS = bluetooth_rfkill_event.o

CFLAGS = -O2 -Wall
CFLAGS += `pkg-config --cflags bluez`
CFLAGS += `pkg-config --cflags glib-2.0`

LIBS += `pkg-config --libs bluez`
LIBS += `pkg-config --libs glib-2.0`

%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

bluetooth_rfkill_event:     $(OBJS)
		$(CC) $(LDFLAGS) $(OBJS) $(LIBS) -o $@

clean:
		$(RM) $(OBJS) bluetooth_rfkill_event

all: bluetooth_rfkill_event

install:
	mkdir -p $(INSTALL_ROOT)/usr/sbin
	install bluetooth_rfkill_event $(INSTALL_ROOT)/usr/sbin
	mkdir -p $(INSTALL_ROOT)/lib/systemd/system
	install bluetooth-rfkill-event.service $(INSTALL_ROOT)/lib/systemd/system
	mkdir -p $(INSTALL_ROOT)/etc/firmware
	install *.conf $(INSTALL_ROOT)/etc/firmware
