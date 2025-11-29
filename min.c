#include <stdint.h>

#define MULTIBOOT_MAGIC        0x1BADB002
#define MULTIBOOT_FLAGS        0
#define MULTIBOOT_CHECKSUM     -(MULTIBOOT_MAGIC + MULTIBOOT_FLAGS)

__attribute__((section(".multiboot")))
const unsigned int multiboot_header[] = {
    MULTIBOOT_MAGIC,
    MULTIBOOT_FLAGS,
    MULTIBOOT_CHECKSUM
};


char ASCII[256];
void ascii_init(){
    for (int i = 0; i < 256; ++i) ASCII[i] = 0;

    ASCII[0x1E] = 'a';
    ASCII[0x30] = 'b';
    ASCII[0x2E] = 'c';
    ASCII[0x20] = 'd';
    ASCII[0x12] = 'e';
    ASCII[0x21] = 'f';
    ASCII[0x22] = 'g';
    ASCII[0x23] = 'h';
    ASCII[0x17] = 'i';
    ASCII[0x24] = 'j';
    ASCII[0x25] = 'k';
    ASCII[0x26] = 'l';
    ASCII[0x32] = 'm';
    ASCII[0x31] = 'n';
    ASCII[0x18] = 'o';
    ASCII[0x19] = 'p';
    ASCII[0x10] = 'q';
    ASCII[0x13] = 'r';
    ASCII[0x1f] = 's';
    ASCII[0x14] = 't';
    ASCII[0x16] = 'u';
    ASCII[0x2f] = 'v';
    ASCII[0x11] = 'w';
    ASCII[0x2d] = 'x';
    ASCII[0x15] = 'y';
    ASCII[0x2c] = 'z';
    ASCII[0x0b] = '0';
    ASCII[0x02] = '1';
    ASCII[0x03] = '2';
    ASCII[0x04] = '3';
    ASCII[0x05] = '4';
    ASCII[0x06] = '5';
    ASCII[0x07] = '6';
    ASCII[0x08] = '7';
    ASCII[0x09] = '8';
    ASCII[0x0a] = '9';
    ASCII[0x39] = ' ';
    ASCII[0x1c] = '\n';

}

volatile uint8_t* VGA = (volatile uint8_t*)0xB8000;
uint8_t     vga_curr_line       =    0;
uint8_t     vga_curr_row        =    0;


char        command_buff[32]    =   {0};
uint8_t     cb_curr             =    0;

static     inline   uint8_t  inb     (uint16_t port);
static     inline   void     outb    (uint16_t port, uint8_t val);
static     inline   uint16_t inw     (uint16_t port);
static     inline   void     outw    (uint16_t port, uint16_t val);
static     inline   uint32_t inl     (uint16_t port);
static     inline   void     outl    (uint16_t port, uint32_t val);

uint8_t     strcmp      (char *str1, char *str2, uint8_t len);
void        byte2hex    (uint8_t val, char *buf);
void        printch     (char c);
void        printstr    (char *ch, uint8_t len);
void        screen_up   (void);
void        clear_cmd   (void);
uint32_t    buf2_l      (char *buf);
uint16_t    buf2_w      (char *buf);
uint8_t     buf2_b      (char *buf);

uint8_t     read_byte   (uint32_t addr);
void memset(uint8_t *dst, uint8_t b, uint16_t sz);


void        command     (void);
void        kbpoll      (void);

uint8_t     last_scancode   =   0;

uint64_t    LAST_VAR        =   0;
void        test_port    (void);

__attribute__((aligned(16)))
static uint8_t kernel_stack[8192];

//############## MEM ###############################################################################################

uint8_t     VAR8[8];
uint16_t    VAR16[8];
uint32_t    VAR32[8];


//########      COMMANDS        #######################################################################################################

void    clear();
void    reboot();
void    in8();
void    in16();
void    in32();
void    out8();
void    out16();
void    out32();
void    read8();
void    read16();
void    read32();
void    read64();
void    hexdump();
void    llv8();
void    llv16();
void    llv32();
void    print_b(uint8_t b);
void    print_w(uint16_t w);
void    print_l(uint32_t l);
void    rvar();
void    write8();


//######################################################################################################################################

void _entry(void){
    asm volatile (
        "movl %[stack_top], %%esp\n\t"
        "xorl %%ebp, %%ebp\n\t"
        :
        : [stack_top] "r" (kernel_stack + sizeof(kernel_stack))
        : "memory"
    );

    ascii_init();
    char *str1 = "penis";
    printstr(str1, 5);

    while(1){
        kbpoll();
    }

}

//№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№№########################################################

void     kbpoll(){
    char ch;
    if(inb(0x64) & 0x1){
        uint8_t d = inb(0x60);

        if (d & 0x80) {
            last_scancode = d;
            return;
        }
        ch = ASCII[d];
        if (ch) {
            printch(ch);
        }
        last_scancode = d;
    }
}


//######################################################################################################################################

void write8(){
    uint32_t addr = buf2_l(&command_buff[7]);
    uint8_t b = buf2_b(&command_buff[16]);
    *((volatile uint8_t*)addr) = b;
}

//read var [b] [num]
void rvar(){
    uint8_t b = buf2_b(&command_buff[5]);
    uint8_t num = buf2_b(&command_buff[8]);
    clear_cmd();
    printstr("\n", 1);
    if(b == 8){
        print_b(VAR8[num]);
    }else if(b == 16){
        print_w(VAR16[num]);
    }else if(b == 32){
        print_l(VAR32[num]);
    }
}

void print_b(uint8_t b){
    char str[3] = {0};
    byte2hex(b, str);
    printstr(str, 2);
}
void print_w(uint16_t w){
    char buf[5] = {0};
    for(int i = 0; i < 2; i++){
        byte2hex((w >> ((1-i)*8)) & 0xFF, buf+ (2*i));
    }
    printstr(buf, 4);
}
void print_l(uint32_t l){
    char buf[9] = {0};
    for(int i = 0; i < 4; i++){
        byte2hex((l >> ((3-i)*8)) & 0xFF, buf+ (2*i));
    }
    printstr(buf, 8);
}

//load last var
void llv8(){
    uint8_t d = buf2_b(&command_buff[5]);
    clear_cmd();
    VAR8[d] = (uint8_t)LAST_VAR;
}

void llv16(){
    uint8_t d = buf2_w(&command_buff[6]);
    clear_cmd();
    VAR16[d] = (uint16_t)LAST_VAR;
}
void llv32(){
    uint8_t d = buf2_l(&command_buff[6]);
    clear_cmd();
    VAR32[d] = (uint32_t)LAST_VAR;
}

void hexdump(){
    uint32_t addr = buf2_l(&command_buff[8]);
    uint16_t bytes = buf2_w(&command_buff[17]);
    clear_cmd();

    char str[80] = {'\0'};
    str[32] = '|';
    uint8_t byte = 0;

    printstr("\n", 1);

    for(int i = 0; i < bytes; i+=8){
        for(int j = 0; j < 8; j++){
            byte = read_byte((addr + i+ j));
            byte2hex(byte, &str[j*4]);
            str[33+j] = (char)byte;
        }
        vga_curr_line = 0;
        printstr(str, 80);
        memset(str, (uint8_t)('\0'), 80 );
        str[32] = '|';
    }
}

void read8(void){
    uint32_t addr = buf2_l(&command_buff[6]);
    clear_cmd();
    uint8_t val = read_byte(addr);
    char str[3] = {0};
    byte2hex(val, str);
    printstr("\n", 1);
    printstr(str, 2);
    LAST_VAR = (uint64_t)val;
}

void read16(void){
    uint32_t addr = buf2_l(&command_buff[7]);
    clear_cmd();
    uint16_t val = 0;
    for(int i = 0; i < 2; i++){
        val |= (uint16_t)read_byte(addr+i) << (i*8);
    }
    LAST_VAR = val;
    char buf[5] = {0};
    for(int i = 0; i < 2; i++){
        byte2hex((val >> ((1-i)*8)) & 0xFF, buf+ (2*i));
    }
    printstr("\n", 3);
    printstr(buf, 4);

}

void  read32() {
    uint32_t addr = buf2_l(&command_buff[7]);
    clear_cmd();
    uint32_t val = 0;
    for(int i = 0; i < 4; i++){
        val |= (uint32_t)read_byte(addr+i) << (i*8);
    }
    LAST_VAR = val;
    char buf[9] = {0};
    for(int i = 0; i < 4; i++){
        byte2hex((val >> ((3-i)*8)) & 0xFF, buf+ (2*i));
    }
    printstr("\n", 3);
    printstr(buf, 8);
}
void  read64() {
    uint32_t addr = buf2_l(&command_buff[7]);
    clear_cmd();
    uint64_t val = 0;
    for(int i = 0; i < 8; i++){
        val |= (uint64_t)read_byte(addr+i) << (i*8);
    }
    LAST_VAR = val;
    char buf[17] = {0};
    for(int i = 0; i < 8; i++){
        byte2hex((val >> ((7-i)*8)) & 0xFF, buf+ (2*i));
    }
    printstr("\n", 3);
    printstr(buf, 16);
}

void  out8(){
    uint16_t port = buf2_w(&command_buff[5]);
    uint8_t val = buf2_b(&command_buff[10]);
    outb(port, val);
    clear_cmd();
}

void  out16(){
    uint16_t port = buf2_w(&command_buff[6]);
    uint16_t val = buf2_w(&command_buff[11]);
    outw(port, val);
    clear_cmd();
}

void  out32(){
    uint16_t port = buf2_w(&command_buff[6]);
    uint32_t val = buf2_l(&command_buff[11]);
    outl(port, val);
    clear_cmd();
}

void in8(void){
    uint16_t port = buf2_w(&command_buff[4]);
    uint8_t val = inb(port);

    clear_cmd();
    char str[2] = {0};
    byte2hex(val, str);

    printstr("\n", 3);
    printstr(str, 2);
    LAST_VAR = (uint64_t)val;
}

void  in16(){
    uint16_t port = buf2_w(&command_buff[5]);
    uint16_t val = inw(port);
    clear_cmd();

    char buf[4] = {0};
    byte2hex((val >> 8) & 0xFF, buf);
    byte2hex(val & 0xFF, buf+2);

    printstr("\n", 2);
    printstr(buf, 4);
    LAST_VAR = (uint64_t)val;
}

void  in32(){
    uint16_t port = buf2_w(&command_buff[5]);
    uint32_t val = inl(port);
    clear_cmd();

    char buf[8] = {0};
    byte2hex((val >> 24) & 0xFF, buf);
    byte2hex((val >> 16) & 0xFF, buf+2);
    byte2hex((val >> 8) & 0xFF, buf+4);
    byte2hex(val & 0xFF, buf+6);

    printstr("\n", 2);
    printstr(buf, 8);

    LAST_VAR = (uint64_t)val;
}


//######################################################################################################################################

void command(){
    if(strcmp("clear", command_buff, 5)){
        clear();
    }else if(strcmp("reboot", command_buff, 6)){
        reboot();
    }else if(strcmp("in8", command_buff, 3)){
        in8();
    }else if(strcmp("in16", command_buff, 4)){
        in16();
    }else if(strcmp("in32", command_buff, 4)){
        in32();
    }else if(strcmp("out8", command_buff, 4)){
        out8();
    }else if(strcmp("out16", command_buff, 5)){
        out16();
    }else if(strcmp("out32", command_buff, 5)){
        out32();
    }else if(strcmp("read8", command_buff, 5)){
        read8();
    }else if(strcmp("read16", command_buff, 6)){
        read16();
    }else if(strcmp("read32", command_buff, 6)){
        read32();
    }else if(strcmp("read64", command_buff, 6)){
        read64();
    }else if(strcmp("hexdump", command_buff, 7)){
        hexdump();
    }else if(strcmp("llv8", command_buff, 4)){
        llv8();
    }else if(strcmp("llv16", command_buff, 4)){
        llv16();
    }else if(strcmp("llv32", command_buff, 4)){
        llv32();
    }else if(strcmp("rvar", command_buff, 4)){
        rvar();
    }else if(strcmp("write8", command_buff, 6)){
        write8();
    }




}

//#####################################################################################################################################


void memset(uint8_t *dst, uint8_t b, uint16_t sz){
    for(int i = 0; i < sz; i++){
        dst[i] = b;
    }
}

uint8_t     read_byte   (uint32_t addr){
    uint8_t val = *((volatile uint8_t*)addr);
    return(val);
}

void     screen_up(){
    for (int y = 1; y < 25; y++)
        for (int x = 0; x < 80; x++) {
            VGA[((y-1)*80 + x)*2] = VGA[(y*80 + x)*2];
            VGA[((y-1)*80 + x)*2 + 1] = VGA[(y*80 + x)*2 + 1];
        }
        for (int x = 0; x < 80; x++) {
            VGA[((25-1)*80 + x)*2] = '\0';
            VGA[((25-1)*80 + x)*2 + 1] = 0x0F;
        }
        vga_curr_line = 0;
}

void     clear_cmd(){
    for(uint8_t i = 0; i < sizeof(command_buff); i++){
        command_buff[i] = '\0';
    }
    cb_curr = 0;
}

void     printch(char c) {
    if (c == '\n') {
        if (cb_curr < sizeof(command_buff))
            command_buff[cb_curr] = '\0';
        else
            command_buff[sizeof(command_buff)-1] = '\0';

        command();
          clear_cmd();
        vga_curr_row++;
        vga_curr_line = 0;
        return;
    } else {
        VGA[(vga_curr_row*80 + vga_curr_line)*2] = c;
        VGA[(vga_curr_row*80 + vga_curr_line)*2 + 1] = 0x0F;
        vga_curr_line++;
    }


    if (cb_curr < (sizeof(command_buff) - 1)) {
        command_buff[cb_curr++] = c;
    }

    if (vga_curr_line >= 80) {
        vga_curr_line = 0;
        vga_curr_row++;
    }

    if (vga_curr_row >= 25) {
        screen_up();
        vga_curr_row = 25 - 1;
    }
}

void     printstr(char *ch, uint8_t len){
    for(int i = 0; i < len; i++){
        printch(ch[i]);
    }

}

uint8_t     strcmp(char *str1, char *str2, uint8_t len){
    for(uint8_t i = 0; i < len; i++){
        if(str1[i] != str2[i]){
            return 0;
        }
    }
    return 1;
}

uint32_t     buf2_l(char *buf){
    uint32_t result = 0;
    for (int i = 0; i < 8; i++) {
        char c = buf[i];
        uint8_t val = 0;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') val = 10 + (c - 'A');
        result = (result << 4) | val;
    }
    return result;
}

uint16_t     buf2_w(char *buf){
    uint16_t result = 0;
    for (int i = 0; i < 4; i++) {
        char c = buf[i];
        uint8_t val = 0;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') val = 10 + (c - 'A');
        result = (result << 4) | val;
    }
    return result;
}

uint8_t     buf2_b(char *buf){
    uint8_t result = 0;
    for (int i = 0; i < 2; i++) {
        char c = buf[i];
        uint8_t val = 0;
        if (c >= '0' && c <= '9') val = c - '0';
        else if (c >= 'a' && c <= 'f') val = 10 + (c - 'a');
        else if (c >= 'A' && c <= 'F') val = 10 + (c - 'A');
        result = (result << 4) | val;
    }
    return result;
}

void     byte2hex(uint8_t val, char *buf) {
    const char hex[] = "0123456789abcdef";
    buf[0] = hex[(val >> 4) & 0xF];
    buf[1] = hex[val & 0xF];
}

void     clear(){
    clear_cmd();
    for(uint8_t i = 0; i < 25; i++){
        screen_up();
    }
    vga_curr_line = 0;
    vga_curr_row = 0;
}

void     reboot(){
    struct { uint16_t limit; uint64_t base; } __attribute__((packed)) idt = {0,0};
    __asm__ volatile (
        "cli\n\t"
        "lidt %0\n\t"
        "int3\n\t"
        :
        : "m"(idt)
    );
    while(1) asm volatile("hlt");
}



static  uint8_t inb(uint16_t port) {
    uint8_t ret;
    __asm__ volatile("inb %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static  void outb(uint16_t port, uint8_t val) {
    __asm__ volatile("outb %0, %1" : : "a"(val), "Nd"(port));
}

static  uint16_t inw(uint16_t port) {
    uint16_t ret;
    __asm__ volatile("inw %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static  void outw(uint16_t port, uint16_t val) {
    __asm__ volatile("outw %0, %1" : : "a"(val), "Nd"(port));
}

static  uint32_t inl(uint16_t port) {
    uint32_t ret;
    __asm__ volatile("inl %1, %0" : "=a"(ret) : "Nd"(port));
    return ret;
}

static  void outl(uint16_t port, uint32_t val) {
    __asm__ volatile("outl %0, %1" : : "a"(val), "Nd"(port));
}

