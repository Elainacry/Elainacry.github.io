如果运行EXP后打不通，注意：
1.偏移量是否正确，除了在IDA确认，还要在==gdb动态调试确定偏移量==(在输入函数下断点，观察栈)
2.地址有没有写错
3.send和sendline，如果send不行，就换成sendline；如果sendline不行，就换成send；一般情况都使用send
4.32位系统进行ROP，注意返回地址和参数的位置，ret一个函数时，后面是接返回地址
5.==64位系统注意栈对齐问题，尝试加上ret_addr==


使用IDA时，除了看伪C代码，==还要看反汇编代码，可能有不同的地方==



p32/p64: 打包一个整数，分别打包为32位或64位
u32/u64:解包一个字符串，得到整数
encode：str->byte
decode:byte->str
平常io.recv()得到的都是字符串，io.send()送去的是字符串。


```bash
cat /flag       #一般情况会给出flag  
ls /root        #查看root文件夹
cat /root/flag  #如果flag藏在root里，获取flag
ls /home        #查看home文件夹    
cat /home/*/flag    #如果flag藏在tmp里，获取flag
ls /tmp         #查看tmp文件夹 
cat /tmp/flag   #如果flag藏在tmp里，获取flag
grep -r "flag{" / 2>/dev/null          #直接全局搜索flag{}形式的字符串
```
==先cat flag
没有就找root、home、tmp
没有就用grep -r "flag{" / 2>/dev/null==