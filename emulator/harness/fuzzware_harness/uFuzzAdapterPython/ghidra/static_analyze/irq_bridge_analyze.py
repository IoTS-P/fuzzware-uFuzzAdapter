# coding:utf-8
import json
import os
import re

from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.symbol import RefType
from ghidra.program.model.mem import MemoryAccessException
from java.lang import Throwable

try:
    bridge_decompiler
except NameError:
    bridge_decompiler = DecompInterface()
    bridge_decompiler.openProgram(currentProgram)

_bridge_hfunc_cache = {}
_bridge_callee_summary_cache = {}
_bridge_global_consumer_cache = {}


def _log(msg):
    try:
        my_debug_log("[IRQ_BRIDGE_STATIC] " + str(msg))
    except Exception:
        print("[IRQ_BRIDGE_STATIC] " + str(msg))


def _int_or_zero(value):
    try:
        if value in (None, '', '0x0', '0', 0):
            return 0
        if isinstance(value, basestring):
            return int(value, 16) if value.lower().startswith('0x') else int(value)
        return int(value)
    except Exception:
        return 0


def _hex(value):
    parsed = _int_or_zero(value)
    return '0x%x' % (parsed & 0xffffffff)


def _hex_list(values, limit=8):
    try:
        vals = list(values)
        out = [_hex(v) for v in vals[:limit]]
        if len(vals) > limit:
            out.append('...')
        return '[' + ','.join(out) + ']'
    except Exception:
        return '[]'


def _func_label(func):
    if not func:
        return 'None'
    try:
        return '%s@%s' % (str(func.getName()), _hex(_function_entry(func)))
    except Exception:
        return 'func@0x0'


def _addr(value):
    try:
        return toAddr(int(value) & 0xffffffff)
    except Exception:
        return None


def _pc_from_op(op):
    try:
        return int(op.getSeqnum().getTarget().getOffset()) & ~1
    except Exception:
        return 0


def _get_hfunc(func):
    if not func:
        return None
    if func in _bridge_hfunc_cache:
        return _bridge_hfunc_cache[func]
    res = bridge_decompiler.decompileFunction(func, 30, ConsoleTaskMonitor())
    if not res:
        return None
    hf = res.getHighFunction()
    _bridge_hfunc_cache[func] = hf
    return hf


def _read_u32(addr):
    try:
        a = toAddr(addr & 0xffffffff)
        block = currentProgram.getMemory().getBlock(a)
        if block is None:
            return None
        return currentProgram.getMemory().getInt(a) & 0xffffffff
    except MemoryAccessException:
        return None
    except Throwable:
        return None
    except Exception:
        return None


def _is_writable_addr(value):
    try:
        block = currentProgram.getMemory().getBlock(toAddr(value & 0xffffffff))
        return block is not None and block.isWrite()
    except Exception:
        return False


def _is_code_addr(value):
    try:
        if value in (None, 0, 0xffffffff):
            return False
        a = toAddr(value & ~1)
        block = currentProgram.getMemory().getBlock(a)
        if block is None:
            return False
        if hasattr(block, 'isExecute') and not block.isExecute():
            return False
        return getFunctionContaining(a) is not None
    except Throwable:
        return False
    except Exception:
        return False


def _function_entry(func):
    try:
        return int(func.getEntryPoint().getOffset()) & ~1
    except Exception:
        return 0


def _func_contains_pc(func, pc):
    try:
        if not func or not pc:
            return False
        return func.getBody().contains(toAddr(pc & ~1))
    except Exception:
        return False


def _resolve_const(vn, depth=0):
    if vn is None or depth > 8:
        return None
    try:
        if vn.isConstant():
            return int(vn.getOffset()) & 0xffffffff
        if vn.isAddress():
            return int(vn.getAddress().getOffset()) & 0xffffffff
        op = vn.getDef()
        if op is None:
            return None
        opc = op.getOpcode()
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT,
                   PcodeOp.INT_SEXT, PcodeOp.SUBPIECE):
            return _resolve_const(op.getInput(0), depth + 1)
        if opc == PcodeOp.PTRSUB or opc == PcodeOp.PTRADD or opc == PcodeOp.INT_ADD:
            a = _resolve_const(op.getInput(0), depth + 1)
            b = _resolve_const(op.getInput(1), depth + 1)
            if a is not None and b is not None:
                return (a + b) & 0xffffffff
        if opc == PcodeOp.INT_SUB:
            a = _resolve_const(op.getInput(0), depth + 1)
            b = _resolve_const(op.getInput(1), depth + 1)
            if a is not None and b is not None:
                return (a - b) & 0xffffffff
        if opc == PcodeOp.LOAD:
            ptr = _resolve_const(op.getInput(1), depth + 1)
            if ptr is not None:
                return _read_u32(ptr)
    except Exception:
        return None
    return None


def _resolve_store_addr(op):
    try:
        if op.getOpcode() != PcodeOp.STORE:
            return None
        return _resolve_const(op.getInput(1))
    except Exception:
        return None


def _addr_offset(addr_obj):
    try:
        return int(addr_obj.getOffset()) & 0xffffffff
    except Exception:
        return 0


def _iter_instructions(func):
    if not func:
        return []
    out = []
    try:
        it = currentProgram.getListing().getInstructions(func.getBody(), True)
        while it.hasNext():
            out.append(it.next())
    except Exception:
        pass
    return out


def _inst_pc(inst):
    try:
        return int(inst.getAddress().getOffset()) & ~1
    except Exception:
        return 0


def _inst_mnemonic(inst):
    try:
        return str(inst.getMnemonicString()).lower()
    except Exception:
        return ''


def _operand_text(inst, op_index):
    try:
        return str(inst.getDefaultOperandRepresentation(op_index)).lower()
    except Exception:
        try:
            return str(inst.getOpObjects(op_index)[0]).lower()
        except Exception:
            return ''


def _dest_reg(inst):
    try:
        reg = inst.getRegister(0)
        if reg:
            return str(reg).lower()
    except Exception:
        pass
    text = _operand_text(inst, 0)
    m = re.search(r'\b(r1[0-5]|r[0-9]|ip|lr|sp|pc)\b', text)
    if m:
        return m.group(1)
    return None


def _read_first_u32_reference(inst):
    try:
        refs = inst.getReferencesFrom()
        for ref in refs:
            try:
                off = _addr_offset(ref.getToAddress())
                val = _read_u32(off)
                if val is not None:
                    return val
            except Exception:
                continue
    except Exception:
        pass
    return None


def _scalar_operand_value(inst, op_index):
    try:
        scalar = inst.getScalar(op_index)
        if scalar is not None:
            return int(scalar.getValue()) & 0xffffffff
    except Exception:
        pass
    text = _operand_text(inst, op_index)
    m = re.search(r'#?(-?0x[0-9a-f]+|-?\d+)', text)
    if not m:
        return None
    try:
        return int(m.group(1), 0) & 0xffffffff
    except Exception:
        return None


def _literal_load_value(inst):
    mnem = _inst_mnemonic(inst)
    if not mnem.startswith('ldr'):
        return (None, None)
    reg = _dest_reg(inst)
    if not reg:
        return (None, None)
    val = _read_first_u32_reference(inst)
    if val is None:
        val = _scalar_operand_value(inst, 1)
    return (reg, val)


def _mov_imm_value(inst):
    mnem = _inst_mnemonic(inst)
    if not mnem.startswith('mov'):
        return (None, None)
    reg = _dest_reg(inst)
    if not reg:
        return (None, None)
    val = _scalar_operand_value(inst, 1)
    return (reg, val)


def _parse_store_addr_from_inst(inst, regs):
    mnem = _inst_mnemonic(inst)
    if not mnem.startswith('str'):
        return None
    text = str(inst).lower()
    m = re.search(r'\[(r1[0-5]|r[0-9]|ip|sp)(?:\s*,\s*#?(-?0x[0-9a-f]+|-?\d+))?', text)
    if not m:
        return None
    base_reg = m.group(1)
    if base_reg not in regs:
        return None
    off = 0
    if m.group(2):
        try:
            off = int(m.group(2), 0)
        except Exception:
            off = 0
    return (regs[base_reg] + off) & 0xffffffff


def _collect_listing_global_stores(func):
    stores = []
    regs = {}
    try:
        for inst in _iter_instructions(func):
            store_addr = _parse_store_addr_from_inst(inst, regs)
            if store_addr is not None and _is_writable_addr(store_addr):
                stores.append(store_addr)
            reg, val = _literal_load_value(inst)
            if reg and val is not None:
                regs[reg] = val
                continue
            reg, val = _mov_imm_value(inst)
            if reg and val is not None:
                regs[reg] = val
    except Exception as e:
        _log('listing store scan failed func=%s err=%s' % (_func_label(func), e))
    return stores


def _call_target_from_inst(inst):
    try:
        ft = inst.getFlowType()
        if not ft or not ft.isCall():
            return None
    except Exception:
        return None
    try:
        flows = inst.getFlows()
        for addr_obj in flows:
            pc = _addr_offset(addr_obj) & ~1
            if _is_code_addr(pc):
                return getFunctionContaining(toAddr(pc))
    except Exception:
        pass
    try:
        refs = inst.getReferencesFrom()
        for ref in refs:
            try:
                if ref.getReferenceType().isCall():
                    pc = _addr_offset(ref.getToAddress()) & ~1
                    if _is_code_addr(pc):
                        return getFunctionContaining(toAddr(pc))
            except Exception:
                continue
    except Exception:
        pass
    return None


def _scan_call_arg_constants(func, call_pc, max_back=12):
    regs = {}
    try:
        listing = currentProgram.getListing()
        inst = listing.getInstructionBefore(toAddr(call_pc & ~1))
        steps = 0
        while inst and steps < max_back:
            if not func.getBody().contains(inst.getAddress()):
                break
            reg, val = _literal_load_value(inst)
            if reg and val is not None and reg not in regs:
                regs[reg] = val
            else:
                reg, val = _mov_imm_value(inst)
                if reg and val is not None and reg not in regs:
                    regs[reg] = val
            inst = listing.getInstructionBefore(inst.getAddress())
            steps += 1
    except Exception as e:
        _log('call arg scan failed func=%s call=%s err=%s' %
             (_func_label(func), _hex(call_pc), e))
    return [regs.get('r0'), regs.get('r1'), regs.get('r2'), regs.get('r3')]


def _collect_irq_evidence_from_listing(handler, result):
    try:
        for inst in _iter_instructions(handler['func']):
            pc = _inst_pc(inst)
            callee = _call_target_from_inst(inst)
            if not callee:
                continue
            result['call_pcs'].append(pc)
            stores = _callee_global_stores(callee)
            for addr in stores:
                result['globals'].add(addr)
            args = _scan_call_arg_constants(handler['func'], pc)
            _log('listing_call irq=%d pc=%s callee=%s args=%s callee_stores=%s' %
                 (handler['irq_num'], _hex(pc), _func_label(callee),
                  _hex_list([x for x in args if x is not None]), _hex_list(stores)))
            for val in args:
                if val is not None and _looks_like_process_object(val):
                    result['objects'].add(val)
                    result['globals'].add((val + 15) & 0xffffffff)
    except Exception as e:
        _log('collect listing irq evidence failed irq=%d err=%s' %
             (handler['irq_num'], e))


def _callee_global_stores(func):
    if not func:
        return []
    if func in _bridge_callee_summary_cache:
        return _bridge_callee_summary_cache[func]
    stores = []
    hf = _get_hfunc(func)
    if hf:
        try:
            for op in hf.getPcodeOps():
                if op.getOpcode() != PcodeOp.STORE:
                    continue
                addr = _resolve_store_addr(op)
                if addr is not None and _is_writable_addr(addr):
                    stores.append(addr)
        except Exception:
            pass
    for addr in _collect_listing_global_stores(func):
        if addr is not None and _is_writable_addr(addr):
            stores.append(addr)
    stores = list(set(stores))
    if stores:
        _log('callee_stores func=%s stores=%s' % (_func_label(func), _hex_list(stores)))
    _bridge_callee_summary_cache[func] = stores
    return stores


def _collect_irq_handlers(vtor):
    handlers = []
    if not vtor or vtor == 0xffffffff:
        return handlers
    for irq_num in range(16, 256):
        entry = _read_u32(vtor + irq_num * 4)
        if entry is None:
            continue
        pc = entry & ~1
        if pc == 0 or pc == 0xffffffff or not _is_code_addr(pc):
            continue
        func = getFunctionContaining(toAddr(pc))
        if func:
            handlers.append({'irq_num': irq_num, 'irq_pc': int(func.getEntryPoint().getOffset()) & ~1, 'func': func})
    return handlers


def _looks_like_process_object(obj_addr):
    if not obj_addr or not _is_writable_addr(obj_addr):
        return False
    thread = _read_u32((obj_addr + 8) & 0xffffffff)
    if thread is None:
        return False
    return _is_code_addr(thread)


def _collect_irq_evidence(handler):
    result = {'globals': set(), 'objects': set(), 'call_pcs': []}
    hf = _get_hfunc(handler['func'])
    if not hf:
        _log('evidence_empty irq=%d pc=%s func=%s reason=no_decompile' %
             (handler['irq_num'], _hex(handler['irq_pc']), _func_label(handler['func'])))
        _collect_irq_evidence_from_listing(handler, result)
        return result
    try:
        for op in hf.getPcodeOps():
            if op.getOpcode() == PcodeOp.STORE:
                addr = _resolve_store_addr(op)
                if addr is not None and _is_writable_addr(addr):
                    result['globals'].add(addr)
            elif op.getOpcode() == PcodeOp.CALL:
                pc = _pc_from_op(op)
                result['call_pcs'].append(pc)
                callee = getFunctionContaining(op.getInput(0).getAddress())
                for addr in _callee_global_stores(callee):
                    result['globals'].add(addr)
                for i in range(1, op.getNumInputs()):
                    val = _resolve_const(op.getInput(i))
                    if val is not None and _looks_like_process_object(val):
                        result['objects'].add(val)
                        # Contiki process_poll-style helpers set a per-process
                        # poll flag near the process object. Treat it as one
                        # possible main-side wake condition, but only after the
                        # object layout has been validated.
                        result['globals'].add((val + 15) & 0xffffffff)
    except Exception as e:
        _log('collect irq evidence failed irq=%d err=%s' % (handler['irq_num'], e))
    _collect_irq_evidence_from_listing(handler, result)
    return result


def _find_branch_from_vn(vn, visited, depth=0):
    if vn is None or depth > 12 or vn in visited:
        return 0
    visited.add(vn)
    try:
        descs = vn.getDescendants()
        while descs.hasNext():
            op = descs.next()
            opc = op.getOpcode()
            pc = _pc_from_op(op)
            if opc == PcodeOp.CBRANCH:
                return pc
            if opc in (PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL,
                       PcodeOp.INT_LESS, PcodeOp.INT_SLESS,
                       PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL,
                       PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.COPY,
                       PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
                out = op.getOutput()
                got = _find_branch_from_vn(out, visited, depth + 1)
                if got:
                    return got
            if pc:
                return pc
    except Exception:
        pass
    return 0


def _load_consumer_from_op(global_addr, func, op):
    ref_pc = _pc_from_op(op)
    cmp_pc = ref_pc
    try:
        got = _find_branch_from_vn(op.getOutput(), set())
        if got:
            cmp_pc = got
    except Exception:
        pass
    return {'global': global_addr, 'func': func, 'ref_pc': ref_pc, 'cmp_pc': cmp_pc}


def _find_consumer_for_global(global_addr):
    global_addr &= 0xffffffff
    if global_addr in _bridge_global_consumer_cache:
        return _bridge_global_consumer_cache[global_addr]

    consumers = []
    seen_pcs = set()
    try:
        refs = getReferencesTo(toAddr(global_addr))
    except Exception:
        refs = []
    for ref in refs:
        try:
            if ref.getReferenceType() == RefType.WRITE:
                continue
            ref_pc = int(ref.getFromAddress().getOffset()) & ~1
            func = getFunctionContaining(ref.getFromAddress())
            if not func or ref_pc in seen_pcs:
                continue
            hf = _get_hfunc(func)
            if hf:
                for op in hf.getPcodeOps(ref.getFromAddress()):
                    if op.getOpcode() == PcodeOp.LOAD:
                        consumers.append(_load_consumer_from_op(global_addr, func, op))
                        seen_pcs.add(ref_pc)
                        break
        except Exception:
            continue

    # Reference metadata can be incomplete for literal-pool/global pcode, so fall
    # back to a direct LOAD-address scan. This is slower but runs only for the
    # small set of IRQ-produced RAM addresses.
    try:
        funcs = currentProgram.getFunctionManager().getFunctions(True)
        for func in funcs:
            hf = _get_hfunc(func)
            if not hf:
                continue
            for op in hf.getPcodeOps():
                if op.getOpcode() != PcodeOp.LOAD:
                    continue
                ptr = _resolve_const(op.getInput(1))
                if ptr != global_addr:
                    continue
                ref_pc = _pc_from_op(op)
                if ref_pc in seen_pcs:
                    continue
                consumers.append(_load_consumer_from_op(global_addr, func, op))
                seen_pcs.add(ref_pc)
    except Exception as e:
        _log('global consumer scan failed global=%s err=%s' % (_hex(global_addr), e))

    _bridge_global_consumer_cache[global_addr] = consumers
    if consumers:
        sample = []
        for con in consumers[:6]:
            sample.append('%s:ref=%s cmp=%s' %
                          (_func_label(con.get('func')),
                           _hex(con.get('ref_pc', 0)),
                           _hex(con.get('cmp_pc', 0))))
        _log('consumer global=%s count=%d sample=[%s]' %
             (_hex(global_addr), len(consumers), ';'.join(sample)))
    else:
        _log('consumer global=%s count=0' % _hex(global_addr))
    return consumers


def _calls_to_func(func):
    refs_out = []
    if not func:
        return refs_out
    try:
        refs = getReferencesTo(func.getEntryPoint())
    except Exception:
        refs = []
    for ref in refs:
        try:
            if ref.getReferenceType().isCall():
                refs_out.append(int(ref.getFromAddress().getOffset()) & ~1)
        except Exception:
            pass
    return refs_out


def _is_main_function(func):
    try:
        return str(func.getName()) == 'main'
    except Exception:
        return False


def _find_main_loop_callsite(func, max_depth=4):
    if not func:
        return 0
    visited = set()
    queue = [(func, 0)]
    fallback = 0
    while queue:
        cur, depth = queue.pop(0)
        if cur in visited or depth > max_depth:
            continue
        visited.add(cur)
        for pc in _calls_to_func(cur):
            caller = getFunctionContaining(toAddr(pc))
            if not caller:
                continue
            if caller != cur and fallback == 0:
                fallback = pc
            if _is_main_function(caller):
                return pc
            if caller not in visited:
                queue.append((caller, depth + 1))
    return fallback


def _choose_avail_pc(consumer_func, entry, main_callread_pc, main_read_pc,
                     main_dt_avail_pc=0):
    # Bridge wake_pc must be before the main_dt read path. Do not fall back to
    # main_dt.avail_pc/callread_pc; those are already too late for main_dt.
    avail = _find_main_loop_callsite(consumer_func)
    if avail:
        return avail

    try:
        entry_pc = int(consumer_func.getEntryPoint().getOffset()) & ~1
    except Exception:
        entry_pc = 0

    bad = set([main_callread_pc & ~1, main_read_pc & ~1, main_dt_avail_pc & ~1])
    if entry_pc and entry_pc not in bad and not _func_contains_pc(consumer_func, main_callread_pc):
        return entry_pc
    return 0


def _valid_bridge_avail_pc(avail_pc, main_callread_pc, main_read_pc,
                           main_dt_avail_pc=0):
    if not avail_pc:
        return False
    avail_pc &= ~1
    if avail_pc == (main_callread_pc & ~1) or avail_pc == (main_read_pc & ~1):
        return False
    if main_dt_avail_pc and avail_pc == (main_dt_avail_pc & ~1):
        return False
    return _is_code_addr(avail_pc)


def _main_dt_func(dt):
    callread = _int_or_zero(dt.get('callread_pc', '0x0')) & ~1
    if not callread:
        return None
    return getFunctionContaining(toAddr(callread))


def _object_thread_matches(obj_addr, main_func):
    if not obj_addr or not main_func:
        _log('object_check obj=%s main=%s match=0 reason=missing' %
             (_hex(obj_addr), _func_label(main_func)))
        return False
    if not _looks_like_process_object(obj_addr):
        _log('object_check obj=%s main=%s match=0 reason=bad_object' %
             (_hex(obj_addr), _func_label(main_func)))
        return False
    # Contiki process object layout: next, name, thread. This is a behavior rule,
    # not a firmware-address special case.
    thread = _read_u32((obj_addr + 8) & 0xffffffff)
    if thread is None:
        _log('object_check obj=%s main=%s match=0 reason=thread_unreadable' %
             (_hex(obj_addr), _func_label(main_func)))
        return False
    thread &= ~1
    if not _is_code_addr(thread):
        _log('object_check obj=%s thread=%s main=%s match=0 reason=thread_not_code' %
             (_hex(obj_addr), _hex(thread), _func_label(main_func)))
        return False
    try:
        thread_func = getFunctionContaining(toAddr(thread))
        matched = _function_entry(thread_func) == _function_entry(main_func)
        _log('object_check obj=%s thread=%s thread_func=%s main=%s match=%d' %
             (_hex(obj_addr), _hex(thread), _func_label(thread_func),
              _func_label(main_func), 1 if matched else 0))
        return matched
    except Throwable:
        _log('object_check obj=%s thread=%s main=%s match=0 reason=throwable' %
             (_hex(obj_addr), _hex(thread), _func_label(main_func)))
        return False
    except Exception:
        _log('object_check obj=%s thread=%s main=%s match=0 reason=exception' %
             (_hex(obj_addr), _hex(thread), _func_label(main_func)))
        return False


def _bridge_key(item):
    return (_hex(item.get('dr', '0x0')).lower(),
            _hex(item.get('main_read_pc', '0x0')).lower(),
            _hex(item.get('main_callread_pc', '0x0')).lower())


def irq_bridge_main(json_path, entry, vtor, indirect_map_path=None):
    _log('start json=%s entry=%s vtor=%s indirect=%s' % (json_path, entry, vtor, indirect_map_path))
    if not json_path or not os.path.exists(json_path):
        return []
    with open(json_path, 'r') as f:
        data = json.load(f)

    main_dts = data.get('main_dt_set', [])
    if not main_dts:
        return []

    confirmed = data.setdefault('irq_bridge_set', [])
    candidates = data.setdefault('irq_bridge_candidates', [])
    existing = set([_bridge_key(x) for x in confirmed] + [_bridge_key(x) for x in candidates])

    handlers = _collect_irq_handlers(_int_or_zero(vtor))
    _log('handlers=%d main_dt=%d' % (len(handlers), len(main_dts)))

    produced_by_irq = []
    for h in handlers:
        try:
            ev = _collect_irq_evidence(h)
            if ev['globals'] or ev['objects']:
                produced_by_irq.append((h, ev))
                _log('handler_evidence irq=%d pc=%s func=%s globals=%s objects=%s calls=%s' %
                     (h['irq_num'], _hex(h['irq_pc']), _func_label(h['func']),
                      _hex_list(ev['globals']), _hex_list(ev['objects']),
                      _hex_list(ev['call_pcs'])))
        except Throwable as e:
            _log('skip irq=%s reason=%s' % (h.get('irq_num'), e))
        except Exception as e:
            _log('skip irq=%s reason=%s' % (h.get('irq_num'), e))
    _log('produced_by_irq=%d' % len(produced_by_irq))

    new_candidates = []
    for dt in main_dts:
        dr = _int_or_zero(dt.get('dr', '0x0'))
        callread = _int_or_zero(dt.get('callread_pc', '0x0')) & ~1
        read_pc = _int_or_zero(dt.get('read_pc', '0x0')) & ~1
        main_dt_avail = _int_or_zero(dt.get('avail_pc', '0x0')) & ~1
        _log('main_dt dr=%s read=%s callread=%s avail=%s consume=%s' %
             (_hex(dr), _hex(read_pc), _hex(callread), _hex(main_dt_avail),
              str(dt.get('consume_pc_set', []))))
        if not dr or not callread or not read_pc:
            _log('skip main_dt dr=%s reason=missing_key read=%s callread=%s' %
                 (_hex(dr), _hex(read_pc), _hex(callread)))
            continue
        key_stub = (_hex(dr).lower(), _hex(read_pc).lower(), _hex(callread).lower())
        if key_stub in existing:
            _log('skip main_dt dr=%s reason=existing_bridge_key' % _hex(dr))
            continue
        mf = _main_dt_func(dt)
        _log('main_dt_func dr=%s func=%s' % (_hex(dr), _func_label(mf)))
        best = None
        for h, ev in produced_by_irq:
            strong = False
            target_object = 0
            for obj in ev['objects']:
                try:
                    if _object_thread_matches(obj, mf):
                        strong = True
                        target_object = obj
                        break
                except Exception:
                    continue
            consumers = []
            for g in ev['globals']:
                try:
                    found = _find_consumer_for_global(g)
                    _log('irq_global_consumers irq=%d dr=%s global=%s count=%d' %
                         (h['irq_num'], _hex(dr), _hex(g), len(found)))
                    consumers.extend(found)
                except Throwable as e:
                    _log('skip consumer global=%s err=%s' % (_hex(g), e))
                except Exception as e:
                    _log('skip consumer global=%s err=%s' % (_hex(g), e))
            _log('irq_candidate_scan dr=%s irq=%d strong=%d target_object=%s globals=%d consumers=%d' %
                 (_hex(dr), h['irq_num'], 1 if strong else 0, _hex(target_object),
                  len(ev['globals']), len(consumers)))
            if not consumers:
                _log('skip irq_for_main_dt dr=%s irq=%d reason=no_consumers' %
                     (_hex(dr), h['irq_num']))
                continue
            for con in consumers:
                avail = _choose_avail_pc(con['func'], entry, callread, read_pc,
                                         main_dt_avail)
                if not _valid_bridge_avail_pc(avail, callread, read_pc,
                                              main_dt_avail):
                    _log('skip consumer dr=%s irq=%d global=%s func=%s ref=%s cmp=%s avail=%s reason=bad_avail' %
                         (_hex(dr), h['irq_num'], _hex(con.get('global', 0)),
                          _func_label(con.get('func')), _hex(con.get('ref_pc', 0)),
                          _hex(con.get('cmp_pc', 0)), _hex(avail)))
                    continue
                score = 10 if strong else 1
                if target_object and con['global'] == ((target_object + 15) & 0xffffffff):
                    score += 1
                else:
                    score += 3
                if _is_main_function(getFunctionContaining(toAddr(avail))):
                    score += 5
                _log('candidate_considered dr=%s irq=%d global=%s func=%s avail=%s cmp=%s strong=%d score=%d' %
                     (_hex(dr), h['irq_num'], _hex(con.get('global', 0)),
                      _func_label(con.get('func')), _hex(avail),
                      _hex(con.get('cmp_pc', 0)), 1 if strong else 0, score))
                item = {
                    'state': 'candidate',
                    'enabled': True,
                    'dr': _hex(dr),
                    'main_callread_pc': _hex(callread),
                    'main_read_pc': _hex(read_pc),
                    'irq_pc': _hex(h['irq_pc']),
                    'irq_num': h['irq_num'],
                    'avail_pc': _hex(avail),
                    'cmp_pc': _hex(con['cmp_pc']),
                    'bridge_global': _hex(con['global']),
                    'target_object': _hex(target_object),
                    'reason': 'object_thread_match' if strong else 'global_consumer',
                    'score': score,
                }
                if best is None or item['score'] > best['score']:
                    best = item
        if best:
            candidates.append(best)
            existing.add(_bridge_key(best))
            new_candidates.append(best)
            _log('candidate dr=%s irq=%s avail=%s cmp=%s reason=%s' %
                 (best['dr'], best['irq_num'], best['avail_pc'], best['cmp_pc'], best['reason']))

    if new_candidates:
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
    return new_candidates
