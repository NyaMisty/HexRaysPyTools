import idaapi

from . import callbacks
import HexRaysPyTools.core.helper as helper


class MemberDoubleClick(callbacks.HexRaysEventHandler):
    def __init__(self):
        super(MemberDoubleClick, self).__init__()

    def handle(self, event, *args):
        hx_view = args[0]
        item = hx_view.item
        if item.citype == idaapi.VDI_EXPR and item.e.op in (idaapi.cot_memptr, idaapi.cot_memref):
            # Look if we double clicked on expression that is member pointer. Then get tinfo_t of  the structure.
            # After that remove pointer and get member name with the same offset
            if item.e.x.op == idaapi.cot_memref and item.e.x.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.x.m
            elif item.e.x.op == idaapi.cot_memptr:
                vtable_tinfo = item.e.x.type
                if vtable_tinfo.is_ptr():
                    vtable_tinfo = vtable_tinfo.get_pointed_object()
                method_offset = item.e.m
                class_tinfo = item.e.x.x.type.get_pointed_object()
                vtable_offset = item.e.x.m
            else:
                func_offset = item.e.m
                struct_tinfo = item.e.x.type.get_pointed_object()
                func_ea = helper.choose_virtual_func_address(helper.get_member_name(struct_tinfo, func_offset))
                if func_ea:
                    idaapi.jumpto(func_ea)
                return 0

            func_name = helper.get_member_name(vtable_tinfo, method_offset)
            func_ea = helper.choose_virtual_func_address(func_name, class_tinfo, vtable_offset)
            if func_ea:
                idaapi.jumpto(func_ea)
                return 1

    def _process_commented_address(self, struct_tinfo, func_offset, item):
        sid = idc.get_struc_id(struct_tinfo.dstr())
        if sid != idaapi.BADADDR:
            sptr = idaapi.get_struc(sid)
            mid = idaapi.get_member_id(sptr, func_offset)
            comment = idaapi.get_member_cmt(mid, False)
            if comment:
                try:
                    commented_address = int(comment, 16)
                    new_comment = self._get_target_func_comment(commented_address, item)
                    self._update_func_comment_and_jump(commented_address, new_comment)
                except:
                    pass

    def _get_commented_address_from_vtable(self, vtable_tinfo, method_offset):
        sid = idc.get_struc_id(vtable_tinfo.get_type_name())
        if sid != idaapi.BADADDR:
            sptr = idaapi.get_struc(sid)
            mid = idaapi.get_member_id(sptr, method_offset)
            comment = idaapi.get_member_cmt(mid, False)
            if comment:
                try:
                    return int(comment, 16)
                except:
                    return None
        return None

callbacks.hx_callback_manager.register(idaapi.hxe_double_click, MemberDoubleClick())
