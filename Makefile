PROJECT = tftpserver
HELPER  = mrepro

# ====================

SOURCE = $(PROJECT).c
HEADERS = $(PROJECT).h $(HELPER).h


CC = clang
CFLAGS = -Wall -g -pthread
LDFLAGS =
OBJECTS = ${SOURCE:.c=.o} $(HELPER).o

$(PROJECT): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $(PROJECT)

$(OBJECTS): $(HEADERS)

clean:
	-rm -f $(PROJECT) $(OBJECTS) *.core
