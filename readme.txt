;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

readme for secure instant messaging system

Language : Python
Program will run on UNIX terminal or other command based input readers

Needed libraries: 
1. pip - comes preinstalled with python 2.7.9 or later
	install manually: http://pip.pypa.io/en/stable/installing/

2. cryptography.io library
	install by running command: $ pip install cryptography
	More info: https://cryptography.readthedocs.org/en/latest/
	
Initiate server on a machine before initiating any clients

>>> Starting server:
	command: python server.py HOST PORT
	HOST is ip address on which server should run
	PORT is port address on which server should run

>>> Starting client:
	command: python client.py HOST PORT
	HOST is ip address of which server is running
	PORT is port address on which server is running
	Once you run the application, press any key to start authentication
	Enter username and password to connect
	Once authenticated, use one of the following commands:
		list - to list all online users
		send USER MESSAGE - send message MESSAGE to user USER

>>> We have pre-registered 3 users on the system. The details are mentioned below:

	1. username - sam
	   password - 123

	2. username - tom
	   password - 456

	3. username - ninja
	   password - 789

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;