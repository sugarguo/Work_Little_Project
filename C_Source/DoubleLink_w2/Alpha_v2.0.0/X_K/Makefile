test:GetOptTest.c libmylib.a
	cc GetOptTest.c libmylib.a -o test
libmylib.a:linkedlist.o
	 ar -crv libmylib.a linkedlist.o
linkedlist.o:linkedlist.c
	cc -c linkedlist.c
.PHONY:clean
clean:
	-rm test libmylib.a linkedlist.o
