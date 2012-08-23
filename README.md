R0ket-Sniffer
=============

For sniffing Microsoft Wireless Keyboards with a CCC R0ket

Keyboard Sniffer

This program was created by Dirk Mattes, Clemens Seibold, Florian
Kaase and Alexander Bobach as a semester project for the
IT-Security basics lecture hold by Dr. Wolf Müller at the Humboldt-
Universität zu Berlin. It's based on the work of Travis Goodspeed
(sniffing keyboards with the next hope badge) and previous tries by
Katja Wolf and Fabian Kaczmarczyck. We worked with a Microsoft
Wireless Comfort Keyboard 5000 as test keyboard. In lack of further
test objects, we can't assure it's working with other keyboards as well.
Configurations may have to be adjusted.

Known problems:

 Sometimes keyboard receives not nearly as much pakets as have been sent.
 To bypass this problem with Microsoft Wireless Comfort Keyboard 5000:

 1) Remove batteries from Keyboard.
 2) Plug Reveiver into Computer. Switch r0ket on.
 3) Put batteries back into keyboard.

 Even after this procedure it can occur that the device only
 notices a keyboard, if a key is hold. A finer configuration
 (#received packets, delay) can probably improve this.


 The right frequency can be interfered by another near frequency.
 The program then will get a wrong MAC-Address, assuming it's the
 right one. A better selection process should solve this problem
 (for example: first collect all addresses that come into question,
 then test for everyone, if pakets can be decoded right.

6. Aug 2012