TARGET = test

SRCS = $(shell find . -type f -name '*.cpp')
SRCS += $(shell find . -type f -name '*.c')

all : $(TARGET)

$(TARGET) : $(SRCS)
	$(CXX) -g -o $@ $(SRCS)

.PHONE: clean

clean:
	$(RM) $(TARGET) *.o
