import gdb
import os
import re
import struct


#slabinfo  显示所有slab cache  slabinfo [slab cache name|slab cache symbol name] <allcpu|allnode|alllist|all>
#slabinfo  kmalloc-512 显示kmalloc-512的详细信息
#slabtrace kmalloc-512 追踪kmalloc-512的申请(watch cpu_slab->freelist)
#trunktrace addr 追踪addr这个堆块的申请和释放
#pagetrace addr 追踪这个page的申请和释放
#hex 转16进制
# TODO：
#通过page结构体获取page地址
po = 14 # 打印对齐偏移
layer = '    '
debug = 0  # Set to 1 to enable debug output, 0 to disable
black = lambda text: f'\033[30m{text}\033[0m' # 黑色，看不见
red = lambda text: f'\033[31m{text}\033[0m' # 红色，刺眼
green = lambda text: f'\033[32m{text}\033[0m' # 绿色，还行
yellow = lambda text: f'\033[33m{text}\033[0m' # 黄色，一般
blue = lambda text: f'\033[34m{text}\033[0m' # 蓝色，比较暗，丑
magenta = lambda text: f'\033[35m{text}\033[0m' # 粉色，好看
cyan = lambda text: f'\033[36m{text}\033[0m' # 浅蓝，好看
white = lambda text: f'\033[37m{text}\033[0m'
max_column = 0
max_task_name = 0


# 地址都用blue显示
# 信息类用green显示
# 描述(结构体名、符号名等)用yellow显示
# 小标题用magenta显示
addr = lambda text: blue(text)
title = lambda text: magenta(text)
info = lambda text: green(text)
disc = lambda text: yellow(text)
stru = lambda text: cyan(text)

debug_print = lambda message: print(magenta("[*] " + message)) if debug == 1 else None
error_print = lambda message: print(red("[x] " + message))


MOD_ALLCPU = 1 << 0
MOD_ALLNODE = 1 << 1
MOD_ALLLIST = 1 << 2
MOD_CACHE = 1 << 3
MOD_CPU = 1 << 4
MOD_NODE = 1 << 5
MOD_ALL = MOD_ALLCPU | MOD_ALLNODE | MOD_ALLLIST
mod_dist = {"allcpu": MOD_ALLCPU, "allnode": MOD_ALLNODE, "alllist": MOD_ALLLIST, "all": MOD_ALL, "cache": MOD_CACHE, "cpu": MOD_CPU, "node": MOD_NODE}
current_cpu = 0
cpus = 1
numa_nodes = 1
cpu_partial = 0 # 是否开启CONFIG_SLUB_CPU_PARTIAL


# 使用type_name类型解析ptr
def get_ptr_content(ptr, type_name):
    return gdb.Value(ptr).cast(gdb.lookup_type(type_name).pointer())

# 检查一个解析项是否有某字段
def has_field(gdb_value, field_name):
    try:
        _ = gdb_value.dereference()[field_name]
        return True
    except Exception:
        return False

# 从linux kernel那拷贝过来的
def bits_list(mask_name):
    mask = None
    if mask is None:
        mask = gdb.parse_and_eval(mask_name + ".bits")
    bits_per_entry = mask[0].type.sizeof * 8
    num_entries = mask.type.sizeof * 8 / bits_per_entry
    entry = -1
    bits = 0

    while True:
        while bits == 0:
            entry += 1
            if entry == num_entries:
                return
            bits = mask[entry]
            if bits != 0:
                bit = 0
                break

        while bits & 1 == 0:
            bits >>= 1
            bit += 1

        cpu = entry * bits_per_entry + bit

        bits >>= 1
        bit += 1

        yield int(cpu)

# 获取NUMA node数量，通过slab_nodes 全局变量的bits获取
def get_nodes():
    nodes_by_mask = 0
    for _ in bits_list('slab_nodes'):
        nodes_by_mask += 1
    return nodes_by_mask

# 获取cpu数量
def get_cpus():
    cpus_by_threads = 0
    for i in gdb.inferiors():
        for _ in i.threads():
            cpus_by_threads += 1

    cpus_by_mask = 0
    for _ in bits_list("__cpu_possible_mask"):
        cpus_by_mask += 1
    
    if cpus_by_threads == cpus_by_mask:
        return cpus_by_mask
    else:
        error_print(f"Get CPUs error, there may be {cpus_by_mask} cpus")
        error_print(f"You can use `set_cpus' cmd to set the actual number of CPUs.")
        return cpus_by_mask
    
def get_current_cpu():
    # 暂时只支持使用qemu进行调试, 根据kernel提供的gdb脚本，qemu模式下这样可以获得cpuid
    if gdb.selected_thread() == None:
        return 0
    else:
        return gdb.selected_thread().num - 1

#获取per_cpu变量当前cpu偏移地址
def get_cpu_offset(cpu_id):
    # 获取__per_cpu_offset
    try:
        return int(gdb.lookup_global_symbol('__per_cpu_offset').value()[cpu_id] & 0xffffffffffffffff)
    except Exception as e:
        error_print("`__per_cpu_offset' does not exist in the current environment")
        error_print(f"get_cpu_offset: {e}")
        raise

#获取per_cpu变量当前cpu偏移地址
def get_current_cpu_offset():
    # 先尝试获取gs_base寄存器
    try:
        return int(gdb.parse_and_eval("$gs_base") & 0xffffffffffffffff)
    except Exception as e:
        error_print("gs_base register does not exist in the current environment")
        error_print(f"get_current_cpu_offset: {e}")
    
    # gs_base寄存器没有的场景下，获取__per_cpu_offset
    get_cpu_offset(current_cpu)



# 返回一个嵌套结构中名字为field_name的成员的field
def find_field(type, field_name):
    for field in type.fields():
        if field.name == field_name:
            return field
        elif field.type.code in [gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION]:
            found = find_field(field.type, field_name)
            if found is not None:
                return found
    return None

# 返回一个嵌套结构中名字为field_name的成员相对结构体的偏移bitpos
def find_field_bitpos(type, field_name, offset=0):
    for field in type.fields():
        if field.name == field_name:
            if field.bitpos is not None:
                return offset + field.bitpos
            else:
                return None
        elif field.type.code in [gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION]:
            found = find_field_bitpos(field.type, field_name, offset + field.bitpos)
            if found is not None:
                return found
    return None

# 类似container_of，已知结构体某个成员的地址，获取结构体起始地址
def get_struct_start(member_address, struct_type_name, member_name):
    try:
        # Lookup the type of the struct
        struct_type = gdb.lookup_type(struct_type_name)
        member_field_bitpos = find_field_bitpos(struct_type, member_name)
        offset = member_field_bitpos // 8  # gdb uses bitpos, so we convert it to bytes
        
        # Compute the address of the start of the struct
        return int(member_address) - offset
    except Exception as e:
        error_print(f"{struct_type_name} does not exist in the current environment")
        error_print(f"get_struct_start: {e}")
        raise


# 打印信息类内容
def print_information(print_data, print_level):
    for data in print_data:
        print(layer * print_level + info("{:<13} : {:<15} {}").format(data["k"], data["v"], data["e"]))
        #print(info(layer + "offset".ljust(po, ' ') + f": {offset} ({hex(offset)})".ljust(name_str_len - po, ' ')) + disc(f"<next ptr's offset in free object>"))

# 组装一个打印指针的格式
def print_ptr_data(ptr, ptr_type, ptr_disc = ""):
    if ptr_disc == "":
        ptr_disc = (str(ptr) + ' ' * 19)[19:].strip()
    return stru(f"({ptr_type})") + addr(f"{hex(ptr)}") + disc(f" {ptr_disc}")

# 小端序转大端序
def swap64(inpnut):
    packed_value = struct.pack('<Q', inpnut)  # 使用小端字节序将整数打包成二进制数据
    swapped_value = struct.unpack('>Q', packed_value)  # 使用大端字节序将二进制数据解包成整数
    return swapped_value[0]

# slab 用的全局变量
# 确定slab page是用struct page 还是struct slab
SlabPageStruct = 'struct slab'
SlabMemberName = 'slab'
IfFreelistHard = True

# 在开启了CONFIG_SLAB_FREELIST_HARDENED
def get_freelisthard_next(next_ptr_address, random):
    next_ptr_value = get_ptr_content(next_ptr_address, "size_t").dereference() # 获取指针的具体值(混淆)
    if random == 0:
        return int(next_ptr_value)
    temp = random ^ int(next_ptr_value)
    next_ptr = temp ^ swap64(next_ptr_address)
    return int(next_ptr)

# 获取一个freelist
def get_freelist(freelist_head, offset, freelist_random):
    try:
        next_obj = int(freelist_head)
        freelist = []
        while next_obj != 0:
            freelist.append(next_obj)
            #obj = gdb.parse_and_eval("(void **)" + str(obj + offset))
            next_ptr = next_obj + offset
            next_obj = get_freelisthard_next(next_ptr, freelist_random)
        return freelist
    except Exception as e:
        error_print(f"error in `get_freelist': {e}")
        raise

# 解析cpuslab 的partial
def get_cpu_slab_partial(cpu_slab, offset, freelist_random):
    global SlabPageStruct
    global SlabMemberName
    if has_field(cpu_slab, 'partial') == False:
        return [], []
    # 高版本使用struct slab表示slab页
    try:
        slab_page = get_ptr_content(cpu_slab.dereference()['partial'], 'struct slab')
        SlabMemberName = 'slab'
    except Exception as e:
        debug_print("kernel version < 5.16, there isn't `struct slab'")

        # 低版本使用struct page
        slab_page = get_ptr_content(cpu_slab.dereference()['partial'], 'struct page')
        SlabPageStruct = 'struct page'
        SlabMemberName = 'page'


    p_page_list = []
    p_freelist = []
    while int(slab_page) != 0:
        p_page_list.append(int(slab_page))
        p_freelist.append(get_freelist(slab_page.dereference()['freelist'], offset, freelist_random))
        slab_page = slab_page.dereference()['next']
        
    return p_page_list, p_freelist

# 打印cpu_slab 的freelist
def show_cpu_freelist(cpu_slab, cpu_id, freelist, print_level, mode):
    print(title(layer * print_level + f"CPU{cpu_id} Slab Freelist: "))
    print(stru(layer * (print_level + 1) + f"({SlabPageStruct} *)") + addr(cpu_slab.dereference()[SlabMemberName]))
    for i in range(len(freelist)):
        if (mode & MOD_ALLLIST == 0) and (i >= 2): # alllist 模式下输出全部，否则输出两个剩下的省略
            print(stru(layer * (print_level + 2) + "-> ......"))
            return 
        print(stru(layer * (print_level + 2) + "-> ") + addr(hex(freelist[i])))


def show_pages_and_freelist(partial_page, partial_freelist, print_level, mode):
    if len(partial_page) == 0:
        print(stru(layer * (print_level + 1) + "None"))
        return 

    for page_id in range(len(partial_page)):
        print(stru(layer * (print_level + 1) + f"({SlabPageStruct} *)") + addr(hex(partial_page[page_id])) + disc(f" <No.{page_id+1} page>"))
        for i in range(len(partial_freelist[page_id])):
            if (mode & MOD_ALLLIST == 0) and (i >= 2): # alllist 模式下输出全部，否则输出两个剩下的省略
                print(stru(layer * (print_level + 2) + "-> ......"))
                return 
            print(stru(layer * (print_level + 2) + "-> ") + addr(hex(partial_freelist[page_id][i])))





# 打印cpu_slab信息，当前只支持打印当前cpu slab信息
def show_cpu_slab(cpu_slab_addr, cpu_id, offset, print_level, mode, freelist_random):
    try:
        cpu_slab = get_ptr_content(cpu_slab_addr, 'struct kmem_cache_cpu')
        
        # 获取cpu_slab 的freelist
        cpu_freelist = get_freelist(cpu_slab.dereference()['freelist'], offset, freelist_random)
        
        # 获取cpu_slab 的partial的各页的freelist
        partial_page, partial_freelist = get_cpu_slab_partial(cpu_slab, offset, freelist_random)
        
        total_objects = len(cpu_freelist) + sum(map(lambda sublist: len(sublist), partial_freelist))
        total_pages = len(partial_page) + 1

        # 打印信息
        print(title(layer * print_level + f"CPU{cpu_id} Slab Info: ") + print_ptr_data(cpu_slab, cpu_slab.type))
        #print(title(layer * print_level + f"CPU{cpu_id} Slab Info: ") + stru("(struct kmem_cache_cpu *)") + addr(f"{hex(cpu_slab_addr)}"))
        print_level += 1
        print_data = []
        print_data.append({'k' : "pages", 'v' : f"{total_pages}", 'e' : ""})
        print_data.append({'k' : "objects", 'v' : f"{total_objects}", 'e' : ""})
        
        print_information(print_data, print_level)
        show_cpu_freelist(cpu_slab, cpu_id, cpu_freelist, print_level, mode)
        print(title(layer * print_level + f"CPU{cpu_id} Slab Partial List: "))
        show_pages_and_freelist(partial_page, partial_freelist, print_level, mode)
    except Exception as e:
        error_print(f"error in `show_cpu_slab': {e}")
        raise



# 从page双向链表获取page列表和freelist 列表，适用于node中的partial和full
def get_page_and_freelist(list_head, offset, freelist_random):
    next_list = list_head['next']
    page_list = []
    freelist = []
    while next_list != list_head.address:
        tmp_page_addr = get_struct_start(next_list, SlabPageStruct, 'slab_list') 
        tmp_page = get_ptr_content(tmp_page_addr, SlabPageStruct)
        page_list.append(int(tmp_page))
        freelist.append(get_freelist(tmp_page.dereference()['freelist'], offset, freelist_random))
        next_list = tmp_page.dereference()['slab_list']['next']
    return page_list, freelist


# 打印node slab的信息
def show_node_slab(slab_cache_node, node_id, offset, print_level, mode, freelist_random):
    try:
        nr_partial = slab_cache_node.dereference()['nr_partial']
        partial = slab_cache_node.dereference()['partial']
        partial_pages, partial_freelist = get_page_and_freelist(partial, offset, freelist_random)
        full_pages = []
        full_freelist = []
        if_full = False
        if has_field(slab_cache_node, 'full'):
            if_full = True
            full_pages = slab_cache_node.dereference()['full']
            full_pages, full_freelist = get_page_and_freelist(full_pages, offset, freelist_random)

        print_data = []
        print(title(layer * print_level + f"Node{node_id} Slab Info: ") + print_ptr_data(slab_cache_node, slab_cache_node.type))
        #print(title(layer * print_level + f"Node{node_id} Slab Info: ") + stru("(struct kmem_cache_node *)") + addr(f"{hex(slab_cache_node)}"))
        print_level += 1

        print_data.append({'k' : "partial pages", 'v' : f"{len(partial_pages)}", 'e' : ""})
        print_data.append({'k' : "has full list", 'v' : f"{if_full}", 'e' : disc(f"<if CONFIG_SLUB_DEBUG>")})
        print_data.append({'k' : "full pages", 'v' : f"{len(full_pages)}", 'e' : ""})
        print_information(print_data, print_level)

        print(title(layer * print_level + f"Node{node_id} Partial List: "))
        show_pages_and_freelist(partial_pages, partial_freelist, print_level, mode)
        print(title(layer * print_level + f"Node{node_id} Slab Full List: "))
        show_pages_and_freelist(full_pages, full_freelist, print_level, mode)
        
    except Exception as e:
        error_print(f"error in `show_node_slab': {e}")
        raise

# 打印一整个slab cache的所有信息
def show_slab_caches(slab_cache, input_name, mode):
    try:
        # 先准备一些基本信息
        name_str = layer + "name".ljust(po, ' ') + f": {slab_cache.dereference()['name'].string()} "
        name_str_len = len(layer + "name".ljust(po, ' ') + f": {slab_cache.dereference()['name'].string()} ")
        obj_size = slab_cache.dereference()['size']
        offset = slab_cache.dereference()['offset']
        page_order = slab_cache.dereference()['oo']['x'] >> 16
        objects = slab_cache.dereference()['oo']['x'] & 0xffff
        # 获取cpu_partial，这可以反映是否开启CONFIG_SLUB_CPU_PARTIAL
        global cpu_partial
        cpu_slab_addr = get_current_cpu_offset() + int(slab_cache.dereference()['cpu_slab'])
        cpu_partial_disc = disc(f"<without CONFIG_SLUB_CPU_PARTIAL>")
        if has_field(get_ptr_content(cpu_slab_addr, 'struct kmem_cache_cpu'), 'partial') != False:
            cpu_partial = slab_cache.dereference()['cpu_partial']
            cpu_partial_disc = disc(f"<max pages in CPU partial list>")

        # 关于cache 名字：打印名字可能跟实际名字不一样，说明共用同一个cache
        print(title("[+] Slab Cache Info: ") + print_ptr_data(slab_cache, slab_cache.type))
        #print(title("[+] Slab Cache Info: ") + stru("(struct kmem_cache *)") + addr(f"{slab_cache}"))
        if (slab_cache.dereference()['name'].string() != input_name):
            name_disc = disc(f"<mergeable slab> ") + info(f"{input_name}") + disc(" merged with this slab-cache")  
        else:
            name_disc = ""

        # 确定是否开启CONFIG_SLAB_FREELIST_HARDENED
        freelist_random = 0
        try:
            freelist_random = slab_cache.dereference()['random']
        except Exception as e:
            debug_print("no CONFIG_SLAB_FREELIST_HARDENED")
        
        # 打印信息
        print_data = []
        print_data.append({'k' : "cache name", 'v' : f"{slab_cache.dereference()['name'].string()}", 'e' : name_disc})
        print_data.append({'k' : "size", 'v' : f"{obj_size} ({hex(obj_size)})", 'e' : disc("<size of one object>")})
        print_data.append({'k' : "offset", 'v' : f"{offset} ({hex(offset)})", 'e' : disc("<next ptr's offset in free object>")})
        print_data.append({'k' : "page order", 'v' : f"{page_order}", 'e' : disc(f"<slab page size: {hex(2 ** page_order * 4096)}>")})
        print_data.append({'k' : "objects", 'v' : f"{objects}", 'e' : disc(f"<{objects} objects per page>")})
        print_data.append({'k' : "CPU partial", 'v' : f"{cpu_partial}", 'e' : cpu_partial_disc})
        if mode & MOD_CACHE:
            print_information(print_data, 1)

        # 打印cpu slab信息，根据MOD_CPU和MOD_ALLCPU判断(打印全部/只打印第一个/不打印)
        if (mode & MOD_CPU):
            print(title("[+] CPU Slab Info: "))
            print_data = [{'k' : "CPUs", 'v' : f"{cpus}", 'e' : disc("<number of CPUs>")},
                        {'k' : "current cpu", 'v' : f"{current_cpu}", 'e':""}]
            print_information(print_data, 1)
            if (mode & MOD_ALLCPU):
                for i in range(cpus):
                    cpu_offset = get_cpu_offset(i)
                    cpu_slab_addr = cpu_offset + int(slab_cache.dereference()['cpu_slab'])
                    cpu_id = i
                    if i == current_cpu: # 编号是当前cpu的话加上描述字符串
                        cpu_id = (f"{current_cpu} \033[33m<current>\033[35m")
                    show_cpu_slab(cpu_slab_addr, cpu_id, offset, 1, mode, freelist_random)
            else:
                cpu_offset = get_current_cpu_offset()
                cpu_slab_addr = cpu_offset + int(slab_cache.dereference()['cpu_slab'])
                show_cpu_slab(cpu_slab_addr, (f"{current_cpu} \033[33m<current>\033[35m"),offset, 1, mode, freelist_random)

        # 打印node信息，根据是否开启MOD_NODE和MOD_ALLNODE判断(打印全部/只打印第一个/不打印)
        if (mode & MOD_NODE):
            print(title("[+] Node Slab Info: "))
            print_information([{'k' : "NUMA nodes", 'v' : f"{numa_nodes}", 'e' : disc("<number of NUMA nodes>")}], 1)
            if (mode & MOD_ALLNODE):        
                for i in range(numa_nodes):
                    cache_node_i = get_ptr_content(slab_cache.dereference()['node'][i], 'struct kmem_cache_node')
                    show_node_slab(cache_node_i, i, offset, 1, mode, freelist_random) #目前只打印node0
            else:
                cache_node_i = get_ptr_content(slab_cache.dereference()['node'][0], 'struct kmem_cache_node')
                show_node_slab(cache_node_i, 0, offset, 1, mode, freelist_random) #目前只打印node0
        

    except Exception as e:
        error_print(f"error in `show_slab_caches': {e}")
        raise


def slab_cache_lists():
    slab_caches = gdb.parse_and_eval("slab_caches")
    first_cache = get_ptr_content(get_struct_start(slab_caches['next'], "struct kmem_cache", "list"), 'struct kmem_cache')
    c = first_cache

    while True:
        yield c
        c = get_ptr_content(get_struct_start(c['list']['next'], "struct kmem_cache", "list"), 'struct kmem_cache')
        if c.dereference()['list'].address == slab_caches.address:
            return

class ShowSlub(gdb.Command):
    """\033[35mThe 'slabinfo' command provides detailed information about a specified slab cache. \033[0m

\033[35mSyntax: \033[0m
    \033[32mslabinfo <slabname> [cache|cpu|node] [allcpu|allnode|alllist|allinfo]\033[0m

\033[35mParameters:\033[0m
    \033[36mslab_cache_name: The 'slab cache name' or 'slab cache symbol name' of the slab cache to be analyzed.\033[0m

\033[35mOptions:\033[0m
    \033[36mcache  : Display the cache's information.
    cpu    : Display the CPU's information.
    node   : Display the node's information.\033[0m

\033[33mIf none of these last three optional arguments is provided, the command will default to printing \033[36m\033[4mall this three.\033[0m
\033[33mIf one or more of these arguments are provided, the command will print only the specified information.\033[0m

    \033[36mallcpu : Display all cpu_slab information of this slab. \033[4mDefaults display current cpu_slab information.\033[24m  
    allnode: Display all node_slab information of this slab. \033[4mDefault display the first node_slab information.\033[24m 
    alllist: Display the complete freelist per slab page. \033[4mDefault display 2 objects in per freelist.\033[24m 
    all    : Display all of the above information comprehensively.\033[0m
    
\033[33mIf no option is provided, \033[36m\033[4mdefault information\033[0m \033[33mwill be displayed.\033[0m

\033[35mExamples:\033[0m
    \033[32mslabinfo kmalloc-256\033[0m 
        \033[33m(show kmalloc-256 cache & cpu(current) & node(first) slab information, display 2 objects per freelist)\033[0m
        \033[32mslabinfo kmalloc-256 cpu\033[0m 
    \033[33m(show kmalloc-256  cpu(current) slab information, display 2 objects per freelist)\033[0m
    \033[32mslabinfo kmalloc-256 allcpu\033[0m
        \033[33m(show kmalloc-256 cache & cpu(all) & node(first) slab information, display 2 objects per freelist)\033[0m
    \033[32mslabinfo kmalloc-256 cpu allcpu\033[0m
        \033[33m(\033[4monly\033[24m show kmalloc-256 cpu(all) slab information, display 2 objects per freelist)\033[0m
    \033[32mslabinfo filp_cachep\033[0m 
        \033[33m(filp_cachep is symbol of `filp' slab cache)\033[0m

\033[33mNote: This command must be used during a gdb debugging session, and requires specific kernel debugging symbols to be available.\033[0m
"""

    def __init__(self):
        super(ShowSlub, self).__init__("slabinfo",
                                       gdb.COMMAND_DATA,
                                       gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        try:
            args = arg.split()
            if len(args) < 1:
                error_print("slabinfo error: cmd must with argument `slab name'")
                return
            slab_name = args[0]
            mode = 0
            for i in args[1:]:
                if i in mod_dist:
                    mode |= mod_dist[i]
            
            # 默认打印所有
            if (mode & (MOD_CACHE | MOD_CPU | MOD_NODE) == 0):
                mode |= (MOD_CACHE | MOD_CPU | MOD_NODE)

            for cache in slab_cache_lists():
                if cache.dereference()['name'].string() == slab_name:
                    show_slab_caches(cache, slab_name, mode)
                    return

            # 通过名字没找到，则可能是全局变量名，则尝试解析这个参数       
            tmp_cache = gdb.parse_and_eval(slab_name)
            if tmp_cache != None:
                cache_address = tmp_cache.address.dereference()
                print(title(f"[+] `{slab_name}' is a symbol: {tmp_cache.address}"))
                show_slab_caches(cache_address, slab_name, mode)
                return 

            # 还没找到，打印错误
            error_print(f"slabinfo error: there isn't slab cache named `{slab_name}'")
        except Exception as e:
            error_print(f"slabinfo error: {e}")

# ===========================================================================================================

#从linux kernel抄过来的，所有进程的迭代器
def task_lists():
    init_task = gdb.parse_and_eval("init_task").address
    t = g = init_task

    while True:
        while True:
            yield t
            t = get_ptr_content(get_struct_start(t['thread_group']['next'], "struct task_struct", "thread_group"), 'struct task_struct')

            if t == g:
                break

        t = g = get_ptr_content(get_struct_start(g['tasks']['next'], "struct task_struct", "tasks"), 'struct task_struct')
        if t == init_task:
            return

# 遍历所有子进程的迭代器
def children_lists(task):
    if int(task.dereference()['children']['next']) == int(task.dereference()['children'].address):
        return
    t = get_ptr_content(get_struct_start(task.dereference()['children']['next'], "struct task_struct", "sibling"), 'struct task_struct')
    list_head = get_ptr_content(get_struct_start(task.dereference()['children']['next'].address, "struct list_head", "next"), 'struct list_head')

    while True:
        yield t
        t = get_ptr_content(get_struct_start(t.dereference()['sibling']['next'], "struct task_struct", "sibling"), 'struct task_struct')
        if t.dereference()['sibling'].address == list_head:
            return

# 遍历所有线程组的迭代器
def thread_group_lists(task):
    first_member = get_ptr_content(get_struct_start(task.dereference()['thread_group']['next'], "struct task_struct", "thread_group"), 'struct task_struct')
    t = first_member

    while True:
        yield t
        t = get_ptr_content(get_struct_start(t['thread_group']['next'], "struct task_struct", "thread_group"), 'struct task_struct')
        if t == first_member:
            return

def check_max_name(name):
    global max_task_name
    if len(name) > max_task_name:
        max_task_name = len(name)

def get_task_by_name(name):
    try:
        result_task = []
        result_task_pid = []
        for task in task_lists():
            task_name = task.dereference()['comm'].string()
            check_max_name(task_name)
            if name == task_name:
                result_task.append(task)
                result_task_pid.append(int(task.dereference()['pid']))
        return result_task, result_task_pid
    except Exception as e:
        error_print(f"get_task_by_name error: {e}")
        raise

def get_task_by_pid(pid):
    try:
        for task in task_lists():
            check_max_name(task.dereference()['comm'].string())
            if pid == int(task.dereference()['pid']):
                return task
        return None
    except Exception as e:
        error_print(f"get_task_by_pid error: {e}")
        raise


# 打印cred 信息
def show_cred(cred, print_level):
    print(title(layer * print_level + "Cred Info: ") + print_ptr_data(cred, cred.type))
    #print_level += 1
    uid, suid, euid, fsuid = int(cred['uid']['val']), int(cred['suid']['val']), int(cred['euid']['val']), int(cred['fsuid']['val'])
    print(layer * print_level + info("uid: {:<5} suid: {:<5} euid: {:<5} fsuid: {:<5}").format(uid, suid, euid, fsuid))
    gid, sgid, egid, fsgid = int(cred['gid']['val']), int(cred['sgid']['val']), int(cred['egid']['val']), int(cred['fsgid']['val'])
    print(layer * print_level + info("gid: {:<5} sgid: {:<5} egid: {:<5} fsgid: {:<5}").format(gid, sgid, egid, fsgid))
    user_ns = cred['user_ns']
    print(layer * print_level + info("user namespace: ") + print_ptr_data(user_ns, user_ns.type))

# 打印线程组信息
def show_thread_group(task, print_level):
    print(title(layer * print_level + "Thread Group:"))
    #print_level += 1
    print_data = layer * print_level + ""
    for tmp_thread in thread_group_lists(task):
        pid = int(tmp_thread.dereference()['pid'])
        name = tmp_thread.dereference()['comm'].string()
        if len(print_data) < max_column:
            print_data += info(f"{pid:<5} : {name:<{max_task_name}} ")
    print(print_data)

# 递归打印子进程树     
def print_children(task, print_level):
    for children in children_lists(task):
        children_pid = int(children.dereference()['pid'])
        childrren_name = children.dereference()['comm'].string()


        print(info(layer * print_level + "- " + f"{children_pid:<3}: {childrren_name:<{max_task_name}} "))
        print_children(children, print_level + 1)


# 打印子进程信息
def show_children(task, print_level):
    print(title(layer * print_level + "Children Tree:"))
    print(info(layer * print_level + "- " + f"{int(task.dereference()['pid']):<3}: {task.dereference()['comm'].string():<{max_task_name}} "))
    print_level += 1
    
    print_children(task, print_level)
    


# 打印namespace信息
def show_namespace(nsproxy, print_level):
    print(title(layer * print_level + "Namespace Info: ") + print_ptr_data(nsproxy, nsproxy.type))
    #print_level += 1
    ns_list = [['UTS','uts_ns'], ['IPC','ipc_ns'], ['mount','mnt_ns'], ['PID','pid_ns_for_children'], ['NET','net_ns'], ['cgroup','cgroup_ns']]

    for nsitem in ns_list:
        ns_name = nsitem[1]
        ns_title = nsitem[0]
        if has_field(nsproxy, ns_name):
            print(layer * print_level + info(f"{ns_title:<6}: ") + print_ptr_data(nsproxy[ns_name], nsproxy[ns_name].type))

def show_task(task):
    try:
        # 先获取一些基本信息
        name = task.dereference()['comm'].string()
        pid = task.dereference()['pid']
        parent = task.dereference()['parent']
        parent_pid = parent.dereference()['pid']
        parent_name = parent.dereference()['comm'].string()
        nsproxy = task.dereference()['nsproxy']
        parent_disc = ""
        if parent_pid == pid:
            parent_disc = disc("<self>")
        cred = task.dereference()['cred']
        children = task.dereference()['children']
        thread_group = task.dereference()['thread_group']

        print(title(f"[+] Task {pid} Info: ") + print_ptr_data(task, task.type))
        print_data = []
        print_data.append({'k' : "name", 'v' : f"{name}", 'e' : ""})
        print_data.append({'k' : "pid", 'v' : f"{pid}", 'e' : ""})
        print_data.append({'k' : "parent", 'v' : f"{parent_pid}: {parent_name} " + print_ptr_data(parent, parent.type), 'e' : parent_disc})
        
        
        print_information(print_data, 1)
        show_cred(cred, 1)
        show_namespace(nsproxy, 1)
        show_thread_group(task, 1)
        show_children(task, 1)
    except Exception as e:
        error_print(f"show_task error: {e}")
        raise


class TaskInfoCmd(gdb.Command):
    """\033[35mDisplay detailed information of a specified task in the Linux kernel.\033[0m

\033[35mSyntax: \033[0m
    \033[32mtaskinfo [pid|name]\033[0m

\033[35mArguments: \033[0m
    \033[36mpid : Display task with this process ID.
    name: Display task with this process NAME.
    None: Display the current task's information\033[0m

\033[35mExamples:\033[0m
    \033[32mtaskinfo 1234  
        \033[33mDisplay information of the task with PID 1234.
    \033[32mtaskinfo init  
        \033[33mDisplay information of the tasks with the name "init".
    \033[32mtaskinfo       
        \033[33mDisplay information of the current task.\033[0m

\033[35mNotes: \033[0m
    \033[33m1. If the task name is not unique (i.e., there are multiple tasks with the same name), the command will display the PIDs of all tasks with that name. You can then run the command again with a specific PID to get information about a particular task.
    
    2. This command must be used during a gdb debugging session, and requires specific kernel debugging symbols to be available.\033[0m
    """
    def __init__(self):
        super(TaskInfoCmd, self).__init__("taskinfo", gdb.COMMAND_DATA, gdb.COMPLETE_NONE)

    def invoke(self, arg, from_tty):
        try:
            global max_column
            max_column = os.get_terminal_size().columns

            if arg == '': # 如果没跟参数，则打印当前进程
                current_task_pptr = get_current_cpu_offset() + int(gdb.lookup_global_symbol("current_task").value().address)
                current_task_ptr = gdb.parse_and_eval("*(struct task_struct **)" + hex(current_task_pptr))
                show_task(get_ptr_content(current_task_ptr, "struct task_struct"))
                return

            args = arg.split()
            
            if args[0].isdigit():
                task = get_task_by_pid(int(args[0]))
                if task is None:
                    error_print(f"Process pid {args[0]} was not found!")
                    return
            else:
                tasks, pids = get_task_by_name(args[0])
                if len(tasks) > 1:
                    print(title(f"[-] More than one process named {args[0]}: ") + stru(f"{pids}"))
                    print(title(f"[-] Please use pid to show the specific process."))
                    return
                elif len(tasks) == 0:
                    error_print(f"No process named {args[0]} was found!")
                    return
                print(title(f"[+] Fount task {args[0]}, pid is: {int(tasks[0]['pid'])}"))
                task = tasks[0]

            show_task(task)
        except Exception as e:
            error_print(f"taskinfo error: {e}")
        

def try_print(temp, if_print):
    if if_print:
        print(temp)

# gdb.value 中有些union 和struct 没有名字，没法对这层使用下标获取，但如果它下一层有带名字的，可以直接跳过这一层通过下一层的名字获取(离谱)
# 所以sub_name 就是记录跟当前层数不等的下标名字层数
# val就是最初传入的值
# if_print 代表是否全打印
def print_fields(type, val, sub_name, print_level, offset, if_print=False, tar_field=None):
    head_info = "/* {:<7}|{:>5}   */ "
    for field in type.fields():
        now_print = if_print
        tmp_sub_name = sub_name.copy() # 当前层获取值的前置下标
        tmp_name = "" 
        if field.name != None:
            tmp_name = field.name
            tmp_sub_name.append(tmp_name)
            tval = val
            for s in tmp_sub_name: # 依次根据前置下标获取到值
                tval = tval[s]
            if (tar_field is not None) and tmp_name == tar_field:
                now_print = True
        elif field.type.code == gdb.TYPE_CODE_STRUCT:
            tmp_name = "struct"
        elif field.type.code == gdb.TYPE_CODE_UNION:
            tmp_name = "union"
        
        curr_offset = (offset + field.bitpos) // 8
        if (field.bitpos % 8) != 0: # 存在单比特字段的情况
            curr_offset = "{}:{}".format(((offset + field.bitpos) // 8), (field.bitpos % 8))
        print_data = disc(head_info.format(curr_offset, field.type.sizeof)) + layer * print_level
        print_data += info(f"{tmp_name} ")
        if field.type.code in [gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION]:
            try_print(print_data + stru("{"), now_print)
            print_fields(field.type,val,tmp_sub_name, print_level + 1, offset + field.bitpos, now_print, tar_field)
            try_print(' ' * len(head_info.format(0, 0)) + layer * print_level + stru("}") + info(f"{tmp_name};"), now_print)        
        else:
            try_print(print_data + stru(f"({tval.type})") + addr(f"{tval}"), now_print)


# 解码结构体
# destruct (struct kmem_cache_cpu *)0xffff88807d82ce60
# destruct 0xffff88807d82ce60 kmem_cache_cpu
# destruct 0xffff88807d82ce68 kmem_cache_cpu.page
# destruct 0xffff88807d82ce60 kmem_cache_cpu partial  打印partial成员的信息、偏移、值
# destruct 0xffff88807d82ce68 kmem_cache_cpu.page partial
class DecodeStructCommand(gdb.Command):
    """\033[35mDisplay detailed information of a specified structure in memory.\033[0m

\033[35mSyntax: \033[0m
    \033[32mdestruct <address> <type> [member]
    destruct <expression> [member]\033[0m

\033[35mArguments: \033[0m 
    \033[36m<address>    : The memory address of the structure instance or a structure member's address.
    <type>       : The type of the structure or type.member(corresponding to the member address above).
    <expression> : A gdb expression of struct like '(struct kmem_cache_cpu *)0xffff88807d82ce60'. 
    [member]     : Optional. The name of a specific member in the structure. \033[0m 

\033[35mExamples: \033[0m
    \033[32mdestruct 0xffff88807d82ce60 kmem_cache_cpu
    destruct (struct kmem_cache_cpu *)0xffff88807d82ce60
        \033[33mDisplay information of the 'kmem_cache_cpu' structure at the address 0xffff88807d82ce60.
    \033[32mdestruct 0xffff888003041a68 kmem_cache.list
        \033[33mDisplay information of the 'kmem_cache' structure whose "list"'s address is 0xffff888003041a68.
    \033[32mdestruct 0xffff88807d82ce60 kmem_cache_cpu partial
    destruct (struct kmem_cache_cpu *)0xffff88807d82ce60 partial
        \033[33mDisplay only the 'partial' member information of the 'kmem_cache_cpu' structure at the address 0xffff88807d82ce60.
    \033[32mstruct 0xffff888003041a68 kmem_cache.list list
        \033[33mDisplay only the 'list' member information of the 'kmem_cache' structure whose "list"'s address is 0xffff888003041a68.\033[0m

\033[35mNotes:  \033[0m
    \033[33m1. The address, structure type, structure member in argument MUST be valid.
    2. This command must be used during a gdb debugging session, and requires specific kernel debugging symbols to be available.\033[0m
    """
    def __init__(self):
        super(DecodeStructCommand, self).__init__("destruct", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        try:
            head = disc("/* {:<7}|{:>5}   */ ".format("offset", "size"))

            pattern = r'struct\s+(.+?)\s*\*\)\s*(0x[a-fA-F0-9]+)\s*(.*)'
            tar_field = None
            parse_result = None
            match = re.search(pattern, arg)
            if match: # 匹配了说明传入的是表达式
                struct_name = match.group(1)
                address = match.group(2)
                if match.group(3) != "": # 制定了特定字段
                    tar_field = match.group(3)
                    
                parse_result = gdb.parse_and_eval(f"*(struct {struct_name} *){address}")

            else:
                args = arg.split()
                if len(args) >= 2:
                    args[0] = gdb.parse_and_eval(args[0])
                    if '.' in args[1]:
                        point_idx = args[1].index(".")
                        struct_name = args[1][:point_idx]
                        field_name = args[1][point_idx + 1:]
                        struct_start = get_struct_start(int(args[0]), "struct " + struct_name, field_name)
                        parse_result = gdb.parse_and_eval(f"* (struct {struct_name} *){hex(struct_start)}")
                    else:
                        struct_name = args[1]
                        field_name = None
                        parse_result = gdb.parse_and_eval(f"*(struct {struct_name} *){hex(args[0])}")
                    if len(args) == 3:
                        tar_field = args[2]

            head += stru("struct " + struct_name)
            print(head)
            if tar_field == None:
                print_fields(parse_result.type, parse_result, [], print_level = 1, offset = 0, if_print=True)
            else:
                print_fields(parse_result.type, parse_result, [], print_level = 1, offset = 0, if_print=False, tar_field = tar_field)

        except Exception as e:
            error_print(f"destruct error: {e}")
            

# This registers our command.
class SetCpus(gdb.Command):
    """\033[35mSet the number of CPUs.\033[0m"""
    
    def __init__(self):
        super(SetCpus, self).__init__("setcpus", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        global cpus
        try:
            cpus = int(arg)
            print(title(f"[+] Set CPUs success, the number of CPUs is ") + info(f"{cpus}"))
        except ValueError:
            error_print("The argument to 'setcpus' must be an integer.")
        


class ShowCpus(gdb.Command):
    """\033[35mShow the number of CPUs.\033[0m"""
    
    def __init__(self):
        super(ShowCpus, self).__init__("cpus", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        global cpus
        print(title(f"[+] The number of CPUs is ") + info(f"{cpus}"))

class SetNodes(gdb.Command):
    """\033[35mSet the number of NUMA nodes.\033[0m"""
    
    def __init__(self):
        super(SetNodes, self).__init__("setnodes", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        global numa_nodes
        try:
            numa_nodes = int(arg)
            print(title(f"[+] Set NUMA nodes success, the number of NUMA nodes is ") + info(f"{numa_nodes}"))
        except ValueError:
            error_print("The argument to 'setnodes' must be an integer.")
        


class ShowNodes(gdb.Command):
    """\033[35mShow the number of NUMA nodes.\033[0m"""
    
    def __init__(self):
        super(ShowNodes, self).__init__("nodes", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        global numa_nodes
        print(title(f"[+] The number of NUMA nodes is ") + info(f"{numa_nodes}"))


class PerCPU(gdb.Command):
    """\033This command prints the address of a percpu variable. \

\033[35mSyntax: \033[0m
    \033[32mpercpu [cpuid] [expression] \033[0m

\033[35mArguments:\033[0m
    \033[36mcpuid     : Optional. Target CPU's id. Default specify the current CPU.
    expression: Optional. The expression for the per_cpu variable's address or symbol(without space). \033[0m

\033[35mExamples:\033[0m
    \033[32mpercpu
        \033[33mDisplay current CPU's per_cpu base address.
    \033[32mpercpu 0x2ce60 
    percpu filp_cachep->cpu_slab   # filp_cachep->cpu_slab == 0x2ce60
    percpu 0 filp_cachep->cpu_sla  # current CPU id is 0
        \033[33mDisplay filp_cachep->cpu_slab's address in current CPU.\033[0m"""
    
    def __init__(self):
        super(PerCPU, self).__init__("percpu", gdb.COMMAND_USER)
        
    def invoke(self, arg, from_tty):
        args = arg.split()

        cpu_id = current_cpu
        percpu_off = 0

        if len(args) >= 2:
            cpu_id = int(args[0])
            percpu_off = int(gdb.parse_and_eval(args[1]))
            
        elif len(args) == 1:
            temp = int(gdb.parse_and_eval(args[0]))
            if temp < cpus:
                cpu_id = temp
            else:
                percpu_off = temp

        print(title('[+] ' + hex(get_cpu_offset(cpu_id) + percpu_off)))

        
def print_init_info():
    pass


def init():
    global current_cpu
    global cpus
    global numa_nodes
    global max_column
    try:
        max_column = os.get_terminal_size().columns
        cpus = get_cpus()
        print(title(f"[+] CPU number : {cpus}"))
        current_cpu = get_current_cpu()
        print(title(f"[+] Current cpu: {current_cpu}"))
    except Exception as e:
        error_print(f"init error, get CPUs error: {e}")

    try:
        numa_nodes = get_nodes()
        print(title(f"[+] NUMA nodes : {numa_nodes}"))
    except Exception as e:
        error_print(f"init error, get NUMA nodes error: {e}")

    print_init_info()


init()
ShowSlub()
ShowCpus()
SetCpus()
SetNodes()
ShowNodes()
TaskInfoCmd()
DecodeStructCommand()
PerCPU()



