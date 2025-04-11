meta:
  id: miles_vfx_shp
  file-extension: miles_vfx_shp
  endian: le
seq:
  - id: version
    type: str
    size: 4
    encoding: ASCII
  - id: number_of_shapes_in_table
    type: s4
  - id: offsets
    type: t_offset
    repeat: expr
    repeat-expr: number_of_shapes_in_table
types:
  t_offset:
    seq:
      - id: shape
        type: s4
      - id: colors
        type: s4
  t_shape:
    seq:
      - id: header
        type: t_header
  t_header:
    seq:
      - id: bounds
        type: s4
      - id: origin
        type: s4
      - id: xmin
        type: s4
      - id: ymin
        type: s4
      - id: xmax
        type: s4
      - id: ymax
        type: s4
  t_body:
    seq:
      - id: size_res_tree
        type: s4
  t_colors:
    seq:
      - id: number_of_colors_in_list
        type: s4
      - id: color
        type: t_color
        repeat: expr
        repeat-expr: number_of_colors_in_list
  t_color:
    seq:
      - id: color_number
        type: u1
      - id: r
        type: u1
      - id: g
        type: u1
      - id: b
        type: u1
        
