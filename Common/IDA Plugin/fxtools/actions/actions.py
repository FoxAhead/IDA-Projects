import ida_kernwin
import ida_typeinf

from . import unspoil
from .array import ActionArray
from .kaitai import local_type_to_kaitai
from .graphml import run


class FxToolsPluginAction(ida_kernwin.action_handler_t):
    root = "FxToolsPlugin"
    label = None

    def __init__(self, core=None):
        self.core = core
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        print('Action', self.name)
        self._activate(ctx)
        return 1

    @property
    def name(self):
        return self.root + ":" + type(self).__name__

    def update(self, ctx):
        # This action is always available.
        return ida_kernwin.AST_ENABLE_ALWAYS

    def _activate(self, ctx):
        raise NotImplementedError("Please Implement this method")


class ActionExportToKaitai(FxToolsPluginAction):
    label = 'ExportToKaitai'

    def update(self, ctx):
        if ctx.widget_type == ida_kernwin.BWN_LOCTYPS:
            ida_kernwin.attach_action_to_popup(ctx.widget, None, self.name, "FxToolsPlugin/")
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

    def _activate(self, ctx):
        local_type_to_kaitai(ctx)


class ActionExportToGraphML(FxToolsPluginAction):
    label = 'ExportToGraphML'

    def _activate(self, ctx):
        run(ctx)


class ActionUnspoil(FxToolsPluginAction):
    label = 'Unspoil'

    def _activate(self, ctx):
        unspoil.run(ctx)


class ActionSplitArray(FxToolsPluginAction):
    label = 'SplitArray'

    def _activate(self, ctx):
        ActionArray().split_array()


class ActionExtractElement(FxToolsPluginAction):
    label = 'ExtractElement'

    def _activate(self, ctx):
        ActionArray().extract_element()


class ActionConvertTo8(FxToolsPluginAction):
    label = 'ConvertTo8'

    def _activate(self, ctx):
        ActionArray().convert_to(ida_typeinf.BT_INT8)


class ActionConvertTo16(FxToolsPluginAction):
    label = 'ConvertTo16'

    def _activate(self, ctx):
        ActionArray().convert_to(ida_typeinf.BT_INT16)


class ActionConvertTo32(FxToolsPluginAction):
    label = 'ConvertTo32'

    def _activate(self, ctx):
        ActionArray().convert_to(ida_typeinf.BT_INT)
