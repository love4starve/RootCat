CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iheaders -pthread
RELEASE_CFLAGS = -Wall -Wextra -O3 -s -Iheaders -pthread
SRC = main.c src/s_crawler.c src/exploit.c src/sudo_auditor.c src/cap_auditor.c src/cron_auditor.c src/sysfile_auditor.c src/spinner.c
OBJ = $(SRC:.c=.o)
TARGET = rootcat

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

release: $(SRC)
	mkdir -p release
	$(CC) $(RELEASE_CFLAGS) -o release/$(TARGET) $(SRC)
	strip --strip-all release/$(TARGET)

clean:
	rm -f $(OBJ) $(TARGET) src/s_crawler

.PHONY: all clean release
