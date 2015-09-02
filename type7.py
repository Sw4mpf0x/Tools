import sys

encrypted_pass=sys.argv[1] 
keyword=["t","f","d",";","k","f","o","A",",",".","i","y","e","w","r","k","l","d","J","K","D"]
n=2
segmented_encrypted_pass=[encrypted_pass[i:i+n] for i in range(0, len(encrypted_pass), n)] 
salt_position=int(segmented_encrypted_pass[0])-1
plaintext_pass=[]

for idx, val in enumerate(segmented_encrypted_pass):
    if idx != 0:
        Current_salt=ord(keyword[salt_position])
        decimal_value=int("0x"+val, 16)
        plaintext_pass.append(chr(Current_salt^decimal_value))
        salt_position+=1
        
print 'The plaintext password is: '+''.join(plaintext_pass)
