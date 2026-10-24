OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = 0xffffffff80000000;
    __kernel_start = .;

    .text ALIGN(4K) :
    {
        *(.text .text.*)
    } :text

    .rodata ALIGN(4K) :
    {
        *(.rodata .rodata.*)
    } :rodata

    .limine_requests ALIGN(4K) :
    {
        KEEP(*(.limine_requests_start))
        KEEP(*(.limine_requests))
        KEEP(*(.limine_requests_end))
    } :data

    .data ALIGN(4K) :
    {
        *(.data .data.*)
    } :data

    .bss ALIGN(4K) :
    {
        *(COMMON)
        *(.bss .bss.*)
    } :data

    .got ALIGN(8) :
    {
        *(.got .got.*)
    } :data

    __kernel_end = .;

    __kernel_text_mapping_start = ADDR(.text);
    __kernel_text_mapping_end = ALIGN(ADDR(.text) + SIZEOF(.text), 4K);
    __kernel_rodata_mapping_start = ADDR(.rodata);
    __kernel_rodata_mapping_end = ALIGN(ADDR(.rodata) + SIZEOF(.rodata), 4K);
    __kernel_data_mapping_start = ADDR(.limine_requests);
    __kernel_data_mapping_end = ALIGN(__kernel_end, 4K);

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame.*)
        *(.note .note.*)
    }
}
