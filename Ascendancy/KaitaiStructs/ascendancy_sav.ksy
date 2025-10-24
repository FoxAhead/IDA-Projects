meta:
  id: ascendancy_sav
  file-extension: ascendancy_sav
  endian: le
seq:
  - id: block0
    type: t_sav_block0
  - id: block1_sizes
    type: t_sav_block1_sizes
  - id: block2
    type: t_sav_block2
  - id: block3_res_tree
    type: t_res_tree
  - id: block4_stars
    type: t_sav_block4_stars
  - id: block5_square
    type: t_sav_block5_squares
  - id: block6_planets
    type: t_sav_block6_planets
  - id: block7_ships
    type: t_sav_block7_ships
  - id: block8_races
    type: t_sav_block8_races
  - id: block9_lanes
    type: t_sav_block9_lanes
  - id: block10
    type: t_sav_block10
  - id: block11
    type: t_sav_block11
  - id: block12_sectors
    type: t_sav_block12_sectors
types:
  t_sav_block0:
    seq:
      - id: day
        type: s4
      - id: races
        type: s4
      - id: unknonwn_08
        type: s4
      - id: z1
        type: s4
        repeat: expr
        repeat-expr: 7
      - id: z2
        type: s4
        repeat: expr
        repeat-expr: 7
      - id: z3
        type: s4
        repeat: expr
        repeat-expr: 7
      - id: ships_num
        type: s4
      - id: planets_num
        type: s4
      - id: techs_num
        type: s4
      - id: unknown_6c
        type: s4
        repeat: expr
        repeat-expr: 2
  t_sav_block1_sizes:
    seq:
      - id: size_res_tree
        type: s4
        valid: 0x1d72
      - id: size_star
        type: s4
        valid: 0x60
      - id: size_planet
        type: s4
        valid: 0x7B
      - id: size_race
        type: s4
        valid: 0x1EE
      - id: magic4
        type: s4
        valid: 0x27
      - id: magic5
        type: s4
        valid: 0x19e
      - id: size_sector
        type: s4
        valid: 0xd
      - id: size_game
        type: s4
        valid: 0x354ef
  t_sav_block2:
    seq:
      - id: day
        type: s4
      - id: unknown1
        type: s4
      - id: planets
        type: s4
      - id: unknown2
        type: s4
      - id: unknown3
        type: s4
      - id: day1
        type: s4
      - id: day2
        type: s4
      - id: day3
        type: s4
  t_res_item:
    seq:
      - id: name
        type: str
        size: 60
        encoding: ascii
        terminator: 0
      - id: cost
        type: u2
      - id: preq
        type: u1
        repeat: expr
        repeat-expr: 5
      - id: next
        type: u1
        repeat: expr
        repeat-expr: 5
      - id: z2
        type: u1
        repeat: expr
        repeat-expr: 2
      - id: type
        type: u1
  t_type11:
    seq:
      - id: w1
        type: s2
        repeat: expr
        repeat-expr: 7
      - id: w2
        type: s2
        repeat: expr
        repeat-expr: 7
  t_res_tree:
    seq:
      - id: num
        type: s2
      - id: items
        type: t_res_item
        repeat: expr
        repeat-expr: 100
      - id: a
        type: t_type11
      - id: b
        type: s4
      - id: c
        type: s4
  t_star:
    seq:
      - id: type
        type: s4
      - id: index
        type: s2
      - id: unknown_6
        type: s2
      - id: position
        type: t_vector3d
      - id: planets_races_bits
        type: u1
      - id: ships_races_bits
        type: u1
      - id: explored_path_to_bits
        type: u1
      - id: explored_bits
        type: u1
      - id: unknown_18
        type: s4
      - id: name
        type: str
        size: 16
        encoding: ascii
        terminator: 0
      - id: lanes
        type: s4
        repeat: expr
        repeat-expr: 6
      - id: lanes_num
        type: s2
      - id: planets
        type: s4
        repeat: expr
        repeat-expr: 5
      - id: planets_num
        type: s2
      - id: z2
        type: s4
  t_sav_block4_stars:
    seq:
      - id: num
        type: s4
      - id: stars
        type: t_star
        repeat: expr
        repeat-expr: num
  t_square:
    seq:
      - id: a
        type: s1
      - id: b
        type: s1
      - id: c
        type: s1
      - id: d
        type: s1
  t_sav_block5_squares:
    seq:
      - id: num
        type: s4
      - id: unknown_49c5
        type: t_square
        repeat: expr
        repeat-expr: num
  t_vector3d:
    seq:
      - id: x
        type: f4
      - id: y
        type: f4
      - id: z
        type: f4
  t_planet:
    seq:
      - id: v
        type: t_vector3d
      - id: star_index
        type: s2
      - id: unknown_e
        type: s2
      - id: p_squares
        type: s4
      - id: size
        type: u2
        enum: planet_size
      - id: type
        type: u2
        enum: planet_type
      - id: surface_squares_num
        type: u2
      - id: total_squares_num
        type: u2
      - id: free_surface_squares_num
        type: s2
      - id: free_orbital_squares_num
        type: s2
      - id: black_squares_num
        type: s2
      - id: z5
        type: s2
      - id: name
        type: str
        size: 30
        encoding: ascii
        terminator: 0
      - id: word42
        type: u2
      - id: industry
        type: u2
      - id: research
        type: u2
      - id: prosperity
        type: s2
      - id: maximum_population
        type: u2
      - id: word4c
        type: s2
      - id: z6
        type: s2
      - id: building_progress
        type: u2
      - id: word52
        type: u2
      - id: building_planet_item_index
        type: u1
      - id: word55
        type: u2
      - id: race_index
        type: u1
      - id: byte58
        type: s1
      - id: byte59
        type: s1
      - id: z7
        type: s4
      - id: unknown_5e
        type: s4
      - id: unknown_62
        type: s4
      - id: unknown_66
        type: s1
      - id: day_colonized
        type: s4
      - id: unknown_6b
        type: s4
      - id: unknown_6f
        type: s4
      - id: unknown_73
        type: s4
      - id: unknown_77
        type: s4
  t_sav_block6_planets:
    seq:
      - id: planets_num
        type: s4
      - id: planets
        type: t_planet
        repeat: expr
        repeat-expr: planets_num
  t_hull_cell:
    seq:
      - id: gizmo_index
        type: s1
      - id: uses_per_turn_left
        type: s2
      - id: active
        type: s4
  t_target:
    seq:
      - id: type
        type: s1
      - id: p_object
        type: s4
  t_ship:
    seq:
      - id: total_weapon_damage
        type: s4
      - id: total_shield_strength
        type: s4
      - id: total_star_lane_drive_potential
        type: s4
      - id: total_star_lane_hyperdrive_potential
        type: s4
      - id: total_drive_max_distance
        type: s4
      - id: unknown_14
        type: s4
      - id: total_generator_power
        type: s4
      - id: total_power_for_drives
        type: s4
      - id: total_scanner_range_per_turn
        type: s4
      - id: cloaking_level
        type: s4
      - id: has_colonizer
        type: s4
      - id: unknown_2c
        type: s4
      - id: unknown_30
        type: s4
      - id: name
        type: str
        size: 28
        encoding: ascii
        terminator: 0
      - id: unknown_50
        type: s2
      - id: day_built
        type: s4
      - id: race_index
        type: s2
      - id: location_type
        type: u1
      - id: p_location
        type: s4
      - id: order
        type: s1
      - id: order_target_object
        type: s4
      - id: unknown_62
        type: s1
      - id: p_cur_hull_cell
        type: s4
      - id: target
        type: t_target
      - id: unknown_6c
        type: t_vector3d
      - id: unknown_78
        type: t_vector3d
      - id: unknown_84
        type: s4
      - id: available_power
        type: s4
      - id: hull_integrity
        type: s4
      - id: current_shield_strength
        type: s4
      - id: available_moves
        type: s4
      - id: full_hull_integrity
        type: s4
      - id: special_effects
        type: s2
      - id: position
        type: t_vector3d
      - id: hull_size
        type: s1
      - id: hull_cells
        type: t_hull_cell
        repeat: expr
        repeat-expr: 25
      - id: hull_cells_num
        type: s4
      - id: gizmos_num
        type: s4  
  t_ship_entry:
    seq:
      - id: index
        type: s4
      - id: ship
        type: t_ship
  t_sav_block7_ships:
    seq:
      - id: ships_num
        type: s4
      - id: ships
        type: t_ship_entry
        repeat: expr
        repeat-expr: ships_num
  t_race:
    seq:
      - id: unknown_00
        type: u1
      - id: unknown_01
        type: u1
      - id: unknown_02
        type: u1
      - id: z
        size: 4
      - id: star
        type: s4
      - id: z1
        type: str
        size: 400
        encoding: ascii
        terminator: 0
      - id: unknown_19b
        type: s2
      - id: unknown_19d
        type: u1
      - id: z2
        type: str
        size: 12
        encoding: ascii
        terminator: 0
      - id: unknown_1aa
        type: s2
      - id: unknown_1ac
        type: s2
      - id: unknown_1ae
        type: s2
      - id: unknown_1b0
        type: s2
      - id: unknown_1b2
        type: s2
        repeat: expr
        repeat-expr: 7
      - id: unknown_1c0
        type: u1
        repeat: expr
        repeat-expr: 7
      - id: unknown_1c7
        type: s2
        repeat: expr
        repeat-expr: 7
      - id: unknown_1d5
        type: s2
      - id: z5
        size: 2
      - id: unknown_1d9
        type: s2
      - id: unknown_1db
        type: s2
      - id: unknown_1dd
        type: s2
        repeat: expr
        repeat-expr: 6
      - id: unknown_1e9
        type: s1
      - id: unknown_1ea
        type: s4
  t_sav_block8_races:
    seq:
      - id: races_num
        type: s4
      - id: race
        type: t_race
        repeat: expr
        repeat-expr: races_num
  t_lane:
    seq:
      - id: p_star1
        type: s4
      - id: p_star2
        type: s4
      - id: vector1
        type: t_vector3d
      - id: vector2
        type: t_vector3d
      - id: unknown_20
        size: 7  
  t_sav_block9_lanes:
    seq:
      - id: num
        type: s4
      - id: lane
        type: t_lane
        repeat: expr
        repeat-expr: num
  t_sav_block10:
    seq:
      - id: z10000
        size: 10000
  t_connection:
    seq:
      - id: stars
        type: s4
        repeat: expr
        repeat-expr: 100
      - id: stars_num
        type: s2
      - id: centroid_position
        type: t_vector3d
  t_sav_block11:
    seq:
      - id: num
        type: s4
      - id: connection
        type: t_connection
        repeat: expr
        repeat-expr: num
  t_sector:
    seq:
      - id: n
        type: s1
      - id: v
        type: t_vector3d
  t_sav_block12_sectors:
    seq:
      - id: num
        type: s4
      - id: sector
        type: t_sector
        repeat: expr
        repeat-expr: num
enums:
  planet_size:
    0: tiny
    1: small
    2: medium
    3: large
    4: enormous
  planet_type:
    0: husk
    1: primordial
    2: congenial
    3: eden
    4: mining
    5: moffet
    6: chapel
    7: cathedral
    8: rich
    9: tycoon
    10: cornucopia
