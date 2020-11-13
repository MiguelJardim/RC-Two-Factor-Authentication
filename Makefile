CC   = gcc
CFLAGS =-g -Wall -Wextra -I../

# A phony target is one that is not really the name of a file
# https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: all clean run

all: pd fs as user

pd:
	cd src && $(CC) $(CFLAGS) pd.c -o pd ../aux/validation.c ../aux/conection.c

fs:
	cd src/FS && $(CC) $(CFLAGS) fs.c -o fs ../../aux/validation.c ../../aux/conection.c

as:
	cd src/AS && $(CC) $(CFLAGS) as.c -o as ../../aux/validation.c ../../aux/conection.c

user:
	cd src && $(CC) $(CFLAGS) user.c -o user ../aux/validation.c ../aux/conection.c

clean:
	@echo Cleaning...
	rm -f src/pd src/AS/as src/user src/FS/fs  

