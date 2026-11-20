OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0x40000000;

    .text ALIGN(4K) :
    {
        *(.text .text.*)
    } :text

    .rodata ALIGN(4K) :
    {
        *(.rodata .rodata.*)
    } :text

    .data ALIGN(4K) :
    {
        *(.data .data.*)
    } :data

    .bss ALIGN(16) :
    {
        *(.bss .bss.*)
        *(COMMON)
    } :data

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame.*)
        *(.note .note.*)
        *(.comment .comment.*)
    }
}
