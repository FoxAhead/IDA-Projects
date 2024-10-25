---------------------------------------------------------------------
The following functions have been adapted for use in high-color (16bpp)
mode, and may behave differently from their 8-bpp counterparts 
(see DEMO.CPP)
---------------------------------------------------------------------

VFX_shape_draw                  
                                        
VFX_shape_translate_draw        

VFX_pixel_write                 
VFX_pixel_read                  

VFX_line_draw                   

VFX_character_draw              

VFX_ILBM_draw                   
VFX_PCX_draw                    
VFX_GIF_draw                    

VFX_pane_wipe                   

VFX_pane_copy                   

VFX_pane_scroll                 

VFX_shape_transform             

VFX_rectangle_hash              

VFX_ellipse_draw                
VFX_ellipse_fill                

VFX_color_scan                  

VFX_flat_polygon                

VFX_translate_polygon           

-----------------------------------------------------------------------
The following functions are NOT currently supported in high-color modes
-----------------------------------------------------------------------

VFX_illuminate_polygon          
VFX_shape_scan                  
VFX_Gouraud_polygon             
VFX_dithered_Gouraud_polygon    
VFX_map_polygon                 

---------------------------------------------------------------------
All other functions are unchanged
---------------------------------------------------------------------

