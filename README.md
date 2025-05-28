# WhisperChain
## COSC55 Security and Privacy 
###  TEAM MEMBERS: Ahmad and ERIN

#### SETUP
run commands:
1. First we need to run `python3 .\server.py` to run our server
2. Then we need our AI moderator to run using the command `python3 .\moderating_AI.py`
3. we also need an admin running using the command `python3 admin.py`
4. then you can run as many clients and servers as you need to
5. it will ask for sign in vs sign up. I would recommend sign up. I haven't throughly tested sigin but I am 90% sure that should work too.


#### COMMANDS LIST
#### THIS WAS SUPPOSED TO HAVE A FRONTEND HENCE A LOT OF THESE COMMANDS WERE MADE KEEPING IN MIND THAT CLICKING SEND BUTTONS OR ETC WOULD AUTOMATICALLY GENERATE THEM BUT SINCE WE ONLY HAVE THE BACKEND DONE, WE NEED TO TYPE THESE COMMANDS MANUALLY

##### COMMAND FOR SERVER
DOES NOT TAKE ANY INPUT

##### COMMAND FOR USER(SENDER AND RECIEVER NAMED AS CLIENT.PY)
1. on start up, when prompted, press `1` to sign in and `2` to sign up
2. then type in your name, password and mode. EACH MUST BE SEPARATED BY COLONS. 
2. NOTE: MODE is right now irrelavent. It was supposed to be another extra credit to allow for differnt kinds of users
3. then you can type `NAME` press enter and then type the person you want to talk to. you can also type `ADMIN userid` to ask admin to unblock someone that the moderator AI blocked for you. 
4. you can also type `REFRESH` to see the names of the current users online
5. once you are talking to a user, you can do `END CALL` to end your messaging with them. `FLAGtext` to flag the text for moderator AI review. other things will be sent as messages to the person

##### COMMAND FOR AI
DOES NOT TAKE ANY INPUT

##### COMMAND FOR ADMIN
ADMIN IS VERY FLEXIBLE AND CAN SEND ANYTHING TO THE SERVER but has 3 useful commands
1. `CURRENT USERS ONLINE`: see users currently online
2. `CURRENT BLOCKED USERS`: see the list of currently blocked users along with who blocked them
3. `UNBLOCK <username> <username>`: UNBLOCK 2nd username from the list of first username. the first person would the one who has blocked someone.