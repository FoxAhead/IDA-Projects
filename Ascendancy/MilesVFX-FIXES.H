

typedef struct
{
   ULONG lxbw;
   ULONG format_level;
   ULONG cpu_os_type;
   ULONG module_version;
   ULONG module_flags;
   ULONG module_num_of_pages;
   ULONG eip_object_num;
   ULONG eip;
   ULONG esp_object_num;
   ULONG esp;
   ULONG page_size;
   ULONG page_offset_shift;
   ULONG fixup_section_size;
   ULONG fixup_section_chksum;
   ULONG loader_section_size;
   ULONG loader_section_chksum;
   ULONG object_table_off;
   ULONG num_objects_in_module;
   ULONG object_page_table_off;
   ULONG object_iter_pages_off;
   ULONG resource_table_off;
   ULONG num_resource_table_entries;
   ULONG resident_name_table_off;
   ULONG entry_table_off;
   ULONG module_directives_off;
   ULONG num_module_directives;
   ULONG fixup_page_table_off;
   ULONG fixup_record_table_off;
   ULONG import_module_table_off;
   ULONG num_import_mod_entries;
   ULONG import_proc_table_off;
   ULONG per_page_chksum_off;
   ULONG data_pages_off;
   ULONG num_preload_pages;
   ULONG nonres_name_table_off;
   ULONG nonres_name_table_len;
   ULONG nonres_name_table_chksum;
   ULONG auto_ds_object_num;
   ULONG debug_info_off;
   ULONG debug_info_len;
   ULONG numinstance_preload;
   ULONG numinstance_demand;
   ULONG heapsize;
}
LX_header_struct;

typedef struct
{
   ULONG virtual_size;
   ULONG reloc_base_addr;
   ULONG object_flags;
   ULONG page_table_index;
   ULONG num_page_table_entries;
   ULONG reserved_space;
}
object_table_struct;

typedef struct
{
   ULONG page_data_offset;
   UWORD  data_size;
   UWORD  flags;
}
object_page_table_struct;

typedef struct
{
   UWORD  type_id;
   UWORD  name_id;
   ULONG resource_size;
   UWORD  object;
   ULONG offset;
}
resource_table_struct;

static void *cdecl DLL_read(ULONG src, ULONG srcoff, ULONG flags, void *dest, ULONG length);


// MOUSE.C

typedef struct             // DPMI real-mode interrupt structure
{
   LONG edi;
   LONG esi;
   LONG ebp;
   LONG reserved;
   LONG ebx;
   LONG edx;
   LONG ecx;
   LONG eax;
   WORD flags;
   WORD es;
   WORD ds;
   WORD fs;
   WORD gs;
   WORD ip;
   WORD cs;
   WORD sp;
   WORD ss;
}
RMI_STRUCT;

