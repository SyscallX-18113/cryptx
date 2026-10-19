
CC = gcc
CFLAGS = -Wall -Wextra -std=c11
LDFLAGS = -lcrypto

TARGET = cryptx
SOURCE = src/main.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) $(SOURCE) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
