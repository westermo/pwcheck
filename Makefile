CFLAGS += -W -Wall -Werror
LIBS = $(LDFLAGS) -lpwquality

OBJS = pwcheck.o

all: pwcheck

pwcheck: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LIBS)

.PHONY: clean

clean:
	$(RM) -f pwcheck $(OBJS)
