CC=g++
CFLAGS= -lpcap -std=c++11
TARGET=test2
SRCS = test2.cpp ./src/sniffer.cpp ./src/capture.cpp ./src/capture_qq.cpp ./src/capture_and_send.cpp

INC = -I ./include

OBJS = $(SRCS:.c=.o)

$(TARGET):$(OBJS)
		$(CC) -o $@ $^ $(CFLAGS)
clean:
		rm -rf $(TARGET)

%.o:%.c
		$(CC) $(CFLAGS) $(INC) -o $@ -c $<
