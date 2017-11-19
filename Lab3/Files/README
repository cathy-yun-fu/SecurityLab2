#Ya-Chi Chuang, 1000665693, yachi.chuang@mail.utoronto.ca
#Cathy Fu, 1000510949, cy.fu@mail.utoronto.ca

Generate QR code:
Common:
We set the value in the url for the "counter=1" for HOTP and "period=30" for TOTP. When secret key is passed in, we convert the secret key into base 2 (convert the character into an integer and shift bits). We then pass our secret key into the function base32_encode to get the base 32 encoded key value. After that, we can get the QR code by combining the secret key with the properly encoded inputs, and corresponding values for counter (HOTP) or period (TOTP).

Validate QR code:
Common:
We initialize HMAC to XOR the secret key with ipad and opad according to the HMAC procedure. 

HOTP:
We make the counter value into a 8 byte array and pass into given sha1 functions. We truncate the value into a 6 digit integer, and we compare the input code with the produced value. If the values are the same, we return true for saying this HOTP is valid, and false for otherwise.

TOTP:
The only difference with HOTP is that instead of counter, we divide our current time with period 30 ( timer = time(null) / 30). After getting the timer value, we put it into a 8 byte array and pass into given sha1 function. We compare the input with our produced integer value. If the values are the same, we return true for saying this TOTP is valid, and false for otherwise.    