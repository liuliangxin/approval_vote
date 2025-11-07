1. root@iZ2vc8286hv0l7xz4b6rglZ:~# pwd
   /root

2. [dfinity-side-projects/bn: Barreto-Naehrig curve implementation and BLS (github.com)](https://github.com/dfinity-side-projects/bn)

3. sudo apt install llvm g++ libgmp-dev libssl-dev

4. git clone https://github.com/dfinity/bn
   cd bn
   make
   make install

5. export LD_LIBRARY_PATH=/lib:/usr/lib:/usr/local/lib

6. 将项目src移动到bn目录下，并转到在awesomeProject中，用go mod

7. go mod init awesomeProject

8. go mod tidy

9. go build

   完了就报错了

![1718628358484](C:\Users\user\AppData\Roaming\Typora\typora-user-images\1718628358484.png)