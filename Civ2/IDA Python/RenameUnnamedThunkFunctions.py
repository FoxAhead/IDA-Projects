import ida_pro
import ida_funcs
import ida_idaapi
import ida_segment
import idautils
import idc

import lib

ida_idaapi.require("lib")


def rename_unnamed_thunk_functions():
    print("[*] Starting thunk functions renaming script...")
    renamed_count = 0

    # Перебираем все функции в текущей базе данных
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        for funcea in idautils.Functions(seg.start_ea, seg.end_ea):
            if lib.func_is_lib(funcea):
                continue
            # Проверяем, является ли функция "thunk"-функцией
            flags = idc.get_func_flags(funcea)
            if not (flags & idc.FUNC_THUNK):
                continue

            # Получаем текущее имя функции
            current_name = idc.get_func_name(funcea)

            # Проверяем, является ли имя дефолтным (sub_XXXXXX)
            # Имена, заданные пользователем или определенные компилятором, пропускаем
            if not current_name.startswith("sub_"):
                continue

            # Получаем адрес, на который ссылается thunk-функция
            func = ida_funcs.get_func(funcea)
            #target_ea, temp_ptr = ida_funcs.calc_thunk_func_target(func)
            temp_ptr = ida_pro.ea_pointer()
            target_ea = ida_funcs.calc_thunk_func_target(func, temp_ptr.cast())

            outtext = "%.8X %s -> %.8X" % (funcea, current_name, target_ea)

            # Если целевой адрес корректен (не BADADDR)
            if target_ea != idc.BADADDR:
                target_name = idc.get_func_name(target_ea)

                outtext = outtext + " %s" % target_name

                if target_name:
                    # Формируем новое имя с префиксом j_
                    new_name = f"j_{target_name}"

                    outtext = outtext + " => %s" % new_name

                    # Пытаемся переименовать функцию
                    if idc.set_name(funcea, new_name, idc.SN_NON_AUTO):
                        print(f"[+] Renamed {current_name} -> {new_name} (targets {hex(target_ea)})")
                        renamed_count += 1
                    else:
                        # Если имя уже занято, добавим адрес для уникальности
                        fallback_name = f"j_{target_name}_{hex(funcea)[2:]}"
                        if idc.set_name(funcea, fallback_name, idc.SN_NON_AUTO):
                            print(f"[!] Name conflict. Renamed {current_name} -> {fallback_name}")
                            renamed_count += 1
                        else:
                            print(f"[-] Failed to rename {current_name} to {new_name}")
            #print(outtext)


#    print(f"[*] Done! Total functions renamed: {renamed_count}")

# Запуск функции
if __name__ == '__main__':
    rename_unnamed_thunk_functions()
