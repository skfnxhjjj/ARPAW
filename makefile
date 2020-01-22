ARPAW :  main.o
	g++ -std=c++14 -o ARPAW main.o -lpcap


main.o : main.cpp
	g++ -std=c++14 -c -o main.o main.cpp -lpcap


clean :
	rm *.o ARPAW