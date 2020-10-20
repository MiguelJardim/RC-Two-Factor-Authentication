CC   = gcc
CFLAGS =-g -Wall -Wextra -I../

# A phony target is one that is not really the name of a file
# https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: all clean run

all: pd fs

pd: pd.c ../aux/validation.c ../aux/conection.c
	$(CC) $(CFLAGS) pd.c -o pd ../aux/validation.c ../aux/conection.c

fs: fs.c ../aux/validation.c ../aux/conection.c
	$(CC) $(CFLAGS) fs.c -o fs ../aux/validation.c ../aux/conection.c

clean:
	@echo Cleaning...
	rm -f pd as user fs  

