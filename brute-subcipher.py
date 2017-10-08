#!/usr/bin/env python
# brute-subcipher.py
# Ex Usage: python brute-subcipher.py lab1/lab1 0x08048520 0x08048511 2>/dev/null
#
# This is just a script I wrote for my own education, both in using python and in scripting with radare2
# Many thanks to the LiveOverflow youtube channel, www.youtube.com/watch?v=y69uIxU0eI8
# gist.github.com/LiveOverflow/3bd87ba4ffc48bda07d82eb4223911fa
# This helped me learn where to get started scripting radare2 and how to get rid of all the r2 output with 2>/dev/null

import sys
import r2pipe


if len(sys.argv) != 4:
    print("Usage: %s <path to file> <breakpoint addr> <breakpoint2 addr>" % sys.argv[0])
    sys.exit(0)

debug_file = sys.argv[1]
#TODO later probably just hardcode these and also their order is weird. bpoint2 comes before bpoint in disass so should really be first
# 0x08048520
bpoint = sys.argv[2]
# 0x08048511
bpoint2 = sys.argv[3]


# Text to try for cipher brute force. This then gets updated with each run and pumped back to rarun2 profile for input
cipher_try="A"
# Create rarun2 profile with input. 
rr2 = debug_file + ".rr2"

def write_rarun2():
    working_rr2 = open(rr2, 'w')
    working_rr2.write('#!/usr/bin/rarun2\n')
    working_rr2.write('program=' + debug_file + "\n")
    working_rr2.write('stdin="' + cipher_try + '"\n')
    working_rr2.write('stdout=\n')
    working_rr2.close()


write_rarun2()
r2 = r2pipe.open(debug_file)
r2.cmd("e dbg.profile=" + rr2)


r2.cmd('aaa')
r2.cmd('ood ' + debug_file)
r2.cmd('db ' + bpoint)
r2.cmd('db ' + bpoint2)
r2.cmd('dc')
decrypted_val = r2.cmd('dr? eax')
r2.cmd('dc')
trying_val = r2.cmd('dr? eax')



# Checks to see if val is printable ASCII, used to tell when decryption phase is done
while True:
    if int(decrypted_val, 0) < 32 or int(decrypted_val, 0) > 126:
        print("Done...Exiting")
        print "Password: " + cipher_try[:-1]
        sys.exit(0)

    if decrypted_val != trying_val:
        # TODO all this can be done in one line and probably better
        tmp = cipher_try[:-1]
        cipher_try = tmp + chr(int(decrypted_val, 0)) + 'A'
        print("New cipher_try: " + cipher_try)

        # write new input to rarun2 (this could be done better than just writing the entire file again)
        write_rarun2()


        r2.cmd('ood')
        r2.cmd('dc')


    decrypted_val = r2.cmd('dr? eax')
    r2.cmd('dc')
    trying_val = r2.cmd('dr? eax')
    r2.cmd('dc')


    
