all: clean
	cd crypt; make; cd ..
	gcc pwman_daemon.c passwd_parser.c -o pwmand
clean:
	cd crypt; make clean; cd ..
	@touch pwmand
	@rm pwmand 
