
option expr32
option casemap:none

; Begin of file winvfx.h
; Begin of file typedefs.h
BOOL32		TYPEDEF		SDWORD

U8		TYPEDEF		BYTE

U16		TYPEDEF		WORD

U32		TYPEDEF		DWORD

C8		TYPEDEF		SBYTE

S8		TYPEDEF		SBYTE

S16		TYPEDEF		SWORD

S32		TYPEDEF		SDWORD

SINGLE		TYPEDEF		REAL4

DOUBLE		TYPEDEF		REAL8

@t_0		TYPEDEF		PTR 
@tag_0		UNION
i		S32		?
u		U32		?
f		SINGLE		?
p		@t_0		?
@tag_0		ENDS

HYBRID		TYPEDEF		@tag_0

YES		EQU		1t
NO		EQU		0t
TRUE		EQU		1t
FALSE		EQU		0t
; End of file typedefs.h
F16		TYPEDEF		SDWORD

F30		TYPEDEF		SDWORD

N_VFX_PREFS		EQU		0t
GIF_SCRATCH_SIZE		EQU		00000502eh
MP_XLAT		EQU		000000001h
MP_XP		EQU		000000002h
ST_XLAT		EQU		000000001h
ST_REUSE		EQU		000000002h
LD_DRAW		EQU		0t
LD_TRANSLATE		EQU		1t
LD_EXECUTE		EQU		2t
PS_NOWRAP		EQU		0t
PS_WRAP		EQU		1t
NO_COLOR		EQU		-1t
VR_NO_MIRROR		EQU		0t
VR_X_MIRROR		EQU		1t
VR_Y_MIRROR		EQU		2t
VR_XY_MIRROR		EQU		3t
PAL_TRANSPARENT		EQU		255t
RGB_TRANSPARENT		EQU		00000fffeh
PL_FREE		EQU		0t
PL_VALID		EQU		1t
PL_CONTAINED		EQU		2t
VWF_BUFF_OWNED		EQU		000000001h
VWF_FRONT_LOCK		EQU		000000002h
VWF_BACK_LOCK		EQU		000000004h
VFC_BLACK_ON_WHITE		EQU		0t
VFC_WHITE_ON_BLACK		EQU		1t
VFC_BLACK_ON_XP		EQU		2t
VFC_WHITE_ON_XP		EQU		3t
@tag_1		STRUCT 1t
X_size		S32		?
Y_size		S32		?
dir		S32		1t DUP (?)
@tag_1		ENDS

VFX_STENCIL		TYPEDEF		@tag_1

@t_1		TYPEDEF		PTR 
_window		STRUCT 1t
buffer		@t_1		?
x_max		S32		?
y_max		S32		?
pixel_pitch		S32		?
bytes_per_pixel		S32		?
R_left		S32		?
R_right		S32		?
R_mask		U32		?
R_width		S32		?
G_left		S32		?
G_right		S32		?
G_mask		U32		?
G_width		S32		?
B_left		S32		?
B_right		S32		?
B_mask		U32		?
B_width		S32		?
flags		S32		?
_window		ENDS

VFX_WINDOW		TYPEDEF		_window

@t_2		TYPEDEF		PTR VFX_WINDOW
_pane		STRUCT 1t
window		@t_2		?
x0		S32		?
y0		S32		?
x1		S32		?
y1		S32		?
_pane		ENDS

PANE		TYPEDEF		_pane

@t_3		TYPEDEF		PTR PANE
@t_4		TYPEDEF		PTR U32
@t_5		TYPEDEF		PTR U32
_pane_list		STRUCT 1t
array		@t_3		?
flags		@t_4		?
user		@t_5		?
list_size		S32		?
_pane_list		ENDS

PANE_LIST		TYPEDEF		_pane_list

@tag_2		STRUCT 1t
r		U8		?
g		U8		?
b		U8		?
@tag_2		ENDS

VFX_RGB		TYPEDEF		@tag_2

@tag_3		STRUCT 1t
color		U8		?
rgb		VFX_RGB		<>
@tag_3		ENDS

VFX_CRGB		TYPEDEF		@tag_3

@tag_4		STRUCT 1t
x		S32		?
y		S32		?
@tag_4		ENDS

VFX_POINT		TYPEDEF		@tag_4

@tag_5		STRUCT 1t
version		S32		?
char_count		S32		?
char_height		S32		?
font_background		S32		?
@tag_5		ENDS

VFX_FONT		TYPEDEF		@tag_5

@tag_6		STRUCT 1t
version		U32		?
shape_count		U32		?
@tag_6		ENDS

VFX_SHAPETABLE		TYPEDEF		@tag_6

@tag_7		STRUCT 1t
x		S32		?
y		S32		?
color		F16		?
u		F16		?
v		F16		?
w		F30		?
@tag_7		ENDS

SCRNVERTEX		TYPEDEF		@tag_7

@tag_8		STRUCT 1t
x0		S32		?
y0		S32		?
x1		S32		?
y1		S32		?
@tag_8		ENDS

VFX_RECT		TYPEDEF		@tag_8

@proto_0		TYPEDEF		PROTO STDCALL :S32, :S32, :S32, :S32, :S32
VFX_set_display_mode		PROTO		@proto_0

@proto_1		TYPEDEF		PROTO STDCALL :PTR VFX_WINDOW, :S32
VFX_lock_window_surface		PROTO		@proto_1

@proto_2		TYPEDEF		PROTO STDCALL :PTR VFX_WINDOW, :S32
VFX_unlock_window_surface		PROTO		@proto_2

@proto_3		TYPEDEF		PROTO STDCALL :S32, :PTR VFX_RGB, :S32
VFX_set_palette_entry		PROTO		@proto_3

@proto_4		TYPEDEF		PROTO STDCALL :S32, :PTR VFX_RGB
VFX_get_palette_entry		PROTO		@proto_4

@proto_5		TYPEDEF		PROTO STDCALL :S32, :S32, :PTR VFX_RGB, :S32
VFX_set_palette_range		PROTO		@proto_5

@proto_6		TYPEDEF		PROTO STDCALL :S32, :S32, :PTR VFX_RGB
VFX_get_palette_range		PROTO		@proto_6

@proto_7		TYPEDEF		PROTO STDCALL :PTR VFX_RGB
VFX_pixel_value		PROTO		@proto_7

@proto_8		TYPEDEF		PROTO STDCALL :U32, :U32, :U32
VFX_triplet_value		PROTO		@proto_8

@proto_9		TYPEDEF		PROTO STDCALL :U32
VFX_RGB_value		PROTO		@proto_9

@proto_10		TYPEDEF		PROTO STDCALL :U32
VFX_color_to_RGB		PROTO		@proto_10

@proto_11		TYPEDEF		PROTO STDCALL :PTR VFX_WINDOW, :U32
VFX_stencil_size		PROTO		@proto_11

@proto_12		TYPEDEF		PROTO STDCALL :PTR VFX_WINDOW, :PTR VFX_STENCIL, :U32
VFX_stencil_construct		PROTO		@proto_12

@proto_13		TYPEDEF		PROTO STDCALL :PTR VFX_STENCIL
VFX_stencil_destroy		PROTO		@proto_13

@proto_14		TYPEDEF		PROTO STDCALL :S32, :S32
VFX_window_construct		PROTO		@proto_14

@proto_15		TYPEDEF		PROTO STDCALL :PTR VFX_WINDOW, :PTR , :S32
VFX_assign_window_buffer		PROTO		@proto_15

@proto_16		TYPEDEF		PROTO STDCALL :PTR VFX_WINDOW
VFX_window_destroy		PROTO		@proto_16

@proto_17		TYPEDEF		PROTO STDCALL :PTR VFX_WINDOW, :S32, :S32, :S32, :S32
VFX_pane_construct		PROTO		@proto_17

@proto_18		TYPEDEF		PROTO STDCALL :PTR PANE
VFX_pane_destroy		PROTO		@proto_18

@proto_19		TYPEDEF		PROTO STDCALL :S32
VFX_pane_list_construct		PROTO		@proto_19

@proto_20		TYPEDEF		PROTO STDCALL :PTR PANE_LIST
VFX_pane_list_destroy		PROTO		@proto_20

@proto_21		TYPEDEF		PROTO STDCALL :PTR PANE_LIST
VFX_pane_list_clear		PROTO		@proto_21

@proto_22		TYPEDEF		PROTO STDCALL :PTR PANE_LIST, :PTR PANE
VFX_pane_list_add		PROTO		@proto_22

@proto_23		TYPEDEF		PROTO STDCALL :PTR PANE_LIST, :PTR VFX_WINDOW, :S32, :S32, :S32, :S32
VFX_pane_list_add_area		PROTO		@proto_23

@proto_24		TYPEDEF		PROTO STDCALL :PTR PANE_LIST, :S32
VFX_pane_list_delete_entry		PROTO		@proto_24

@proto_25		TYPEDEF		PROTO STDCALL :PTR PANE_LIST, :S32, :S32
VFX_pane_list_identify_point		PROTO		@proto_25

@proto_26		TYPEDEF		PROTO STDCALL :PTR PANE_LIST, :S32
VFX_pane_list_get_entry		PROTO		@proto_26

@proto_27		TYPEDEF		PROTO STDCALL :PTR PANE_LIST, :S32
VFX_pane_entry_user_value		PROTO		@proto_27

@proto_28		TYPEDEF		PROTO STDCALL :PTR PANE_LIST, :S32, :U32
VFX_set_pane_entry_user_value		PROTO		@proto_28

@proto_29		TYPEDEF		PROTO STDCALL :PTR PANE_LIST
VFX_pane_list_refresh		PROTO		@proto_29

@proto_30		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :S32, :S32, :S32, :U32
VFX_line_draw		PROTO		@proto_30

@proto_31		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :S32, :S32, :S32, :U32
VFX_rectangle_draw		PROTO		@proto_31

@proto_32		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :S32, :S32, :S32, :U32
VFX_rectangle_fill		PROTO		@proto_32

@proto_33		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR VFX_SHAPETABLE, :S32, :S32, :S32
VFX_shape_draw		PROTO		@proto_33

@proto_34		TYPEDEF		PROTO STDCALL :PTR U8
VFX_shape_lookaside		PROTO		@proto_34

@proto_35		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR VFX_SHAPETABLE, :S32, :S32, :S32
VFX_shape_translate_draw		PROTO		@proto_35

@proto_36		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR VFX_SHAPETABLE, :S32, :S32, :S32, :PTR , :S32, :S32, :S32, :U32
VFX_shape_transform		PROTO		@proto_36

@proto_37		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR VFX_SHAPETABLE, :S32, :S32, :S32, :PTR , :S32, :S32, :S32, :U32, :PTR 
VFX_shape_area_translate		PROTO		@proto_37

@proto_38		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :U32
VFX_shape_remap_colors		PROTO		@proto_38

@proto_39		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32, :S32, :S32, :S32, :PTR VFX_RECT
VFX_shape_visible_rectangle		PROTO		@proto_39

@proto_40		TYPEDEF		PROTO STDCALL :PTR PANE, :U32, :S32, :S32, :PTR VFX_SHAPETABLE
VFX_shape_scan		PROTO		@proto_40

@proto_41		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32
VFX_shape_bounds		PROTO		@proto_41

@proto_42		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32
VFX_shape_origin		PROTO		@proto_42

@proto_43		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32
VFX_shape_resolution		PROTO		@proto_43

@proto_44		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32
VFX_shape_minxy		PROTO		@proto_44

@proto_45		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32, :PTR VFX_RGB
VFX_shape_palette		PROTO		@proto_45

@proto_46		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32, :PTR VFX_CRGB
VFX_shape_colors		PROTO		@proto_46

@proto_47		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :S32, :PTR VFX_CRGB
VFX_shape_set_colors		PROTO		@proto_47

@proto_48		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE
VFX_shape_count		PROTO		@proto_48

@proto_49		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :PTR U32
VFX_shape_list		PROTO		@proto_49

@proto_50		TYPEDEF		PROTO STDCALL :PTR VFX_SHAPETABLE, :PTR U32
VFX_shape_palette_list		PROTO		@proto_50

@proto_51		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :U32
VFX_pixel_write		PROTO		@proto_51

@proto_52		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32
VFX_pixel_read		PROTO		@proto_52

@proto_53		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :S32, :S32, :U32
VFX_rectangle_hash		PROTO		@proto_53

@proto_54		TYPEDEF		PROTO STDCALL :PTR PANE, :U32
VFX_pane_wipe		PROTO		@proto_54

@proto_55		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :PTR PANE, :S32, :S32, :S32
VFX_pane_copy		PROTO		@proto_55

@proto_56		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR PANE
VFX_pane_stretch		PROTO		@proto_56

@proto_57		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR PANE, :PTR S32, :PTR S32
VFX_pane_locate		PROTO		@proto_57

@proto_58		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :S32, :S32
VFX_pane_scroll		PROTO		@proto_58

@proto_59		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :S32, :S32, :U32
VFX_ellipse_draw		PROTO		@proto_59

@proto_60		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :S32, :S32, :U32
VFX_ellipse_fill		PROTO		@proto_60

@proto_61		TYPEDEF		PROTO STDCALL :PTR VFX_POINT, :PTR VFX_POINT, :PTR VFX_POINT, :S32, :S32, :S32
VFX_point_transform		PROTO		@proto_61

@proto_62		TYPEDEF		PROTO STDCALL :S32, :PTR F16, :PTR F16
VFX_Cos_Sin		PROTO		@proto_62

@proto_63		TYPEDEF		PROTO STDCALL :F16, :F16, :PTR F16
VFX_fixed_mul		PROTO		@proto_63

@proto_64		TYPEDEF		PROTO STDCALL 
VFX_default_system_font		PROTO		@proto_64

@proto_65		TYPEDEF		PROTO STDCALL :S32
VFX_default_font_color_table		PROTO		@proto_65

@proto_66		TYPEDEF		PROTO STDCALL :PTR VFX_FONT
VFX_font_height		PROTO		@proto_66

@proto_67		TYPEDEF		PROTO STDCALL :PTR VFX_FONT, :S32
VFX_character_width		PROTO		@proto_67

@proto_68		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :PTR VFX_FONT, :S32, :PTR 
VFX_character_draw		PROTO		@proto_68

@proto_69		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :S32, :PTR VFX_FONT, :PTR SBYTE, :PTR 
VFX_string_draw		PROTO		@proto_69

@proto_70		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR 
VFX_ILBM_draw		PROTO		@proto_70

@proto_71		TYPEDEF		PROTO STDCALL :PTR , :PTR VFX_RGB
VFX_ILBM_palette		PROTO		@proto_71

@proto_72		TYPEDEF		PROTO STDCALL :PTR 
VFX_ILBM_resolution		PROTO		@proto_72

@proto_73		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :PTR 
VFX_PCX_draw		PROTO		@proto_73

@proto_74		TYPEDEF		PROTO STDCALL :PTR , :S32, :PTR VFX_RGB
VFX_PCX_palette		PROTO		@proto_74

@proto_75		TYPEDEF		PROTO STDCALL :PTR 
VFX_PCX_resolution		PROTO		@proto_75

@proto_76		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR 
VFX_GIF_draw		PROTO		@proto_76

@proto_77		TYPEDEF		PROTO STDCALL :PTR , :PTR VFX_RGB
VFX_GIF_palette		PROTO		@proto_77

@proto_78		TYPEDEF		PROTO STDCALL :PTR 
VFX_GIF_resolution		PROTO		@proto_78

@proto_79		TYPEDEF		PROTO STDCALL :PTR PANE, :PTR U32
VFX_color_scan		PROTO		@proto_79

@proto_80		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :PTR SCRNVERTEX
VFX_flat_polygon		PROTO		@proto_80

@proto_81		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :PTR SCRNVERTEX
VFX_Gouraud_polygon		PROTO		@proto_81

@proto_82		TYPEDEF		PROTO STDCALL :PTR PANE, :F16, :S32, :PTR SCRNVERTEX
VFX_dithered_Gouraud_polygon		PROTO		@proto_82

@proto_83		TYPEDEF		PROTO STDCALL :PTR U8
VFX_map_lookaside		PROTO		@proto_83

@proto_84		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :PTR SCRNVERTEX, :PTR VFX_WINDOW, :U32
VFX_map_polygon		PROTO		@proto_84

@proto_85		TYPEDEF		PROTO STDCALL :PTR PANE, :S32, :PTR SCRNVERTEX, :PTR 
VFX_translate_polygon		PROTO		@proto_85

@proto_86		TYPEDEF		PROTO STDCALL :PTR PANE, :F16, :S32, :PTR SCRNVERTEX
VFX_illuminate_polygon		PROTO		@proto_86

; End of file winvfx.h
