# whisper
nodejs application that encrypts all messages between users diffie-hellman so that no middle-man, including the server, can read your messages.

# setup
Run setup.bash to set up npm and the sqlite db.
Run node with a command line argument of some free port `n`, ie 10790. 

The program will use ports `[n, n+4]`, and is accessable at `localhost:n`. If the program is not running on localhost, or not running on https, subtle crypto is blocked by the browser as per this specification "Access to the WebCrypto API is restricted to secure origins (which is to say https:// pages)" (https://www.chromium.org/blink/webcrypto).
