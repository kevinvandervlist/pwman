all:	clean
	@cd libpwman; make; cd ..; cd pwmand; make; cd ..
	gcc example.c -o example -Llibpwman -lpwman -Ilibpwman
	cp example example2
	cp example example3

clean:
	@touch example
	@rm example
	@touch example2
	@rm example2
	@touch example3
	@rm example3

run:	
	@echo export LD_LIBRARY_PATH=libpwman/
	@echo ./example
	@echo ./example2
	@echo ./example3
