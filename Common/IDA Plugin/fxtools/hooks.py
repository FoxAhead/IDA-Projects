import ida_kernwin
import ida_hexrays


class HxeHooks(ida_hexrays.Hexrays_Hooks):
    cnt = 0
    ea = 0

    def __init__(self, actions):
        self.actions = actions
        ida_hexrays.Hexrays_Hooks.__init__(self)

    def populating_popup(self, widget, popup_handle, vu):
        for name, data in self.actions.items():
            label, shortcut = data
            ida_kernwin.attach_action_to_popup(
                vu.ct,
                popup_handle,
                name,
                "FxToolsPlugin/"
            )
        return 0
