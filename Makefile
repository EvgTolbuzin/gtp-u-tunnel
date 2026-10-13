CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -O3

TARGET = tun
SRCS = src/tun.cpp src/globals.cpp src/utils.cpp src/handlers.cpp
OBJS = $(SRCS:.cpp=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)