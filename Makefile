CC = gcc
SRC = main.c block.c
TARGET = tcp-block

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC) -lpcap

clean:
	rm -f $(TARGET)