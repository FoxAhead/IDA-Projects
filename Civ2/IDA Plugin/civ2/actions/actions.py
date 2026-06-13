import ida_kernwin


class ActionManager:

    def __init__(self):
        self._registered_actions = []

    def register_action(self, action, shortcut=None):
        if ida_kernwin.register_action(ida_kernwin.action_desc_t(
                action.name,
                action.label,
                action,
                shortcut)):
            self._registered_actions.append(action)
        else:
            ida_kernwin.warning("Civ2Plugin: failed to register action")

    def unload(self):
        # self._hooks.unhook()
        # self._hooks = None
        self.unregister_actions()

    def unregister_actions(self):
        for action in self._registered_actions:
            ida_kernwin.unregister_action(action.name)


class Civ2PluginAction(ida_kernwin.action_handler_t):
    root = "Civ2Plugin"
    #cnt = 0

    def __init__(self, ucb=None, acb=None, wt=None):
        super().__init__()
        self.update_callback = ucb
        self.activate_callback = acb
        self.widget_types = wt

    @property
    def name(self):
        return Civ2PluginAction.root + ":" + type(self).__name__

    def activate(self, ctx):
        print('Action', self.name)
        if self.activate_callback:
            self.activate_callback(ctx)
        self._activate(ctx)
        return 1

    def _activate(self, ctx):
        raise NotImplementedError("Please Implement this method")

    def update(self, ctx):
        active = self._update(ctx)
        if self.update_callback and not self.update_callback(ctx):
            active = False
        elif self.widget_types is not None and ctx.widget_type not in self.widget_types:
            active = False
        ida_kernwin.attach_action_to_popup(ctx.widget, None, self.name, Civ2PluginAction.root + "/")
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if active else ida_kernwin.AST_DISABLE_FOR_WIDGET

    def _update(self, ctx):
        return True
