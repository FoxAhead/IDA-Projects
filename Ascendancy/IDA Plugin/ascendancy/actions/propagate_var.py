import ida_hexrays
import ida_kernwin

from ascendancy.actions import AscendancyPluginAction


class ActionPropagateVar(AscendancyPluginAction):
    label = "Propagate variable"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.eas = set()

    def _activate(self, ctx):
        if e0 := self.get_curr_var_asg_expr(ctx):
            if e0.ea in self.eas:
                self.eas.remove(e0.ea)
            else:
                self.eas.add(e0.ea)

    def _update(self, ctx):
        if e0 := self.get_curr_var_asg_expr(ctx):
            if e0.ea in self.eas:
                ida_kernwin.update_action_label(self.name, "Don't propagate variable")
            else:
                ida_kernwin.update_action_label(self.name, "Propagate variable")
            return True
        return False

    def get_curr_var_asg_expr(self, ctx):
        if ctx.widget_type != ida_kernwin.BWN_PSEUDOCODE:
            # ida_kernwin.warning("Not ida_kernwin.BWN_PSEUDOCODE")
            return None
        vu = ida_hexrays.get_widget_vdui(ctx.widget)
        if not (vu.get_current_item(ida_hexrays.USE_KEYBOARD) and vu.item.is_citem() and vu.item.e.op == ida_hexrays.cot_var):
            # ida_kernwin.warning("Please position the cursor on variable")
            return None
        e1 = vu.item.e
        e0 = vu.cfunc.body.find_parent_of(e1)
        if e0.op != ida_hexrays.cot_asg:
            # ida_kernwin.warning("Please position the cursor on left-hand variable")
            return None
        return e0
