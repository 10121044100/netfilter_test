.SUFFIXES : .c
 
OBJECT = netfilter_test.o
SRC = netfilter_test.c
 
CC = gcc
CFLAGS = -lnetfilter_queue -W -Wall

TARGET = netfilter_test
 
$(TARGET) : $(OBJECT)
	@echo "------------------------------------"
	@echo [Complie] netfilter_test
	$(CC) -o $(TARGET) $(OBJECT) $(CFLAGS)
	@echo [OK] netfilter_test
	@echo "------------------------------------"
	rm -rf $(OBJECT)
 
clean :
	rm -rf $(OBJECT) $(TARGET)

new :
	@$(MAKE) -s clean
	@$(MAKE) -s

netfilter_test.o : netfilter_test.c
