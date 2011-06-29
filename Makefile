all:	
	@cd libpwman; make; cd ..; cd pwmand; make; cd ..; cd examples; make; cd ..

clean:
	@cd libpwman; make clean; cd ..; cd pwmand; make clean; cd ..; cd examples; make clean; cd ..