gcc -m32 -ffreestanding -fno-stack-protector -O2 -c min.c -o min.o


ld -m elf_i386 -T linker.ld -o kern.bin min.o

cp kern.bin /boot/kern.bin
