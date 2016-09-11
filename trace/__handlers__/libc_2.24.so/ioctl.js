/*
 * Copyright (c) 2016, Forest Crossman <cyrozap@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 */

/*
 * For full API reference, see: http://www.frida.re/docs/javascript-api/
 */

{
    /**
     * Called synchronously when about to call ioctl.
     *
     * @this {object} - Object allowing you to store state for use in onLeave.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {array} args - Function arguments represented as an array of NativePointer objects.
     * For example use Memory.readUtf8String(args[0]) if the first argument is a pointer to a C string encoded as UTF-8.
     * It is also possible to modify arguments by assigning a NativePointer object to an element of this array.
     * @param {object} state - Object allowing you to keep state across function calls.
     * Only one JavaScript function will execute at a time, so do not worry about race-conditions.
     * However, do not use this to store function arguments across onEnter/onLeave, but instead
     * use "this" which is an object for keeping state local to an invocation.
     */
    onEnter: function (log, args, state) {
        this.file = state.fd_map[args[0]];

        /* Some IOC definitions */
        _IOC_NRBITS = 8;
        _IOC_TYPEBITS = 8;
        _IOC_SIZEBITS = 14;
        _IOC_DIRBITS = 2;
        _IOC_NRMASK = ((1 << _IOC_NRBITS)-1);
        _IOC_TYPEMASK = ((1 << _IOC_TYPEBITS)-1);
        _IOC_SIZEMASK = ((1 << _IOC_SIZEBITS)-1);
        _IOC_DIRMASK = ((1 << _IOC_DIRBITS)-1);
        _IOC_NRSHIFT = 0;
        _IOC_TYPESHIFT = (_IOC_NRSHIFT+_IOC_NRBITS);
        _IOC_SIZESHIFT = (_IOC_TYPESHIFT+_IOC_TYPEBITS);
        _IOC_DIRSHIFT = (_IOC_SIZESHIFT+_IOC_SIZEBITS);
        _IOC_NONE = 0;
        _IOC_WRITE = 1;
        _IOC_READ = 2;
        function _IOC_DIR(nr) {
            return (((nr) >> _IOC_DIRSHIFT) & _IOC_DIRMASK);
        }
        function _IOC_TYPE(nr) {
            return (((nr) >> _IOC_TYPESHIFT) & _IOC_TYPEMASK);
        }
        function _IOC_NR(nr) {
            return (((nr) >> _IOC_NRSHIFT) & _IOC_NRMASK);
        }
        function _IOC_SIZE(nr) {
            return (((nr) >> _IOC_SIZESHIFT) & _IOC_SIZEMASK);
        }

        raw_ioc_dir = _IOC_DIR(args[1]);
        ioc_write = raw_ioc_dir & _IOC_WRITE;
        ioc_read = raw_ioc_dir & _IOC_READ;
        if (ioc_read && ioc_write) {
            this.ioc_dir = "_IOWR";
        } else if (ioc_read) {
            this.ioc_dir = "_IOR";
        } else if (ioc_write) {
            this.ioc_dir = "_IOW";
        } else {
            this.ioc_dir = "_IO";
        }

        this.ioc_type = _IOC_TYPE(args[1]);
        this.ioc_nr = _IOC_NR(args[1]);
        this.ioc_size = _IOC_SIZE(args[1]);

        ioc_string = this.ioc_dir + "(0x" + this.ioc_type.toString(16) + ", 0x" + this.ioc_nr.toString(16);
        if (this.ioc_dir !== "_IO") {
            ioc_string += ", " + this.ioc_size;
        }
        ioc_string += ")";

        this.ioc_data_address = args[2];

        log("ioctl(" + "file=\"" + this.file + "\" (fd=" + args[0] + "), request=" + ioc_string + ", ...)");
        if (this.file.indexOf("/dev/mali") > -1) {
            if ((this.ioc_dir === "_IOWR") || (this.ioc_dir === "_IOW")) {
                ioc_data = Memory.readByteArray(this.ioc_data_address, this.ioc_size);
                this.uk_id = Memory.readU32(this.ioc_data_address);
                if (this.uk_id === 0) {
                    log("  write -> UKP_FUNC_ID_CHECK_VERSION:");
                    log("    Major version: 0x" + Memory.readU16(this.ioc_data_address.add(8)).toString(16));
                    log("    Minor version: 0x" + Memory.readU16(this.ioc_data_address.add(10)).toString(16));
                } else if (this.uk_id >= 512) {
                    switch(this.uk_id - 512) {
                        case 0:
                            log("  write -> KBASE_FUNC_MEM_ALLOC:");
                            log("    va_pages:     0x" + Memory.readU64(this.ioc_data_address.add(8)).toString(16));
                            log("    commit_pages: 0x" + Memory.readU64(this.ioc_data_address.add(16)).toString(16));
                            log("    extent:       0x" + Memory.readU64(this.ioc_data_address.add(24)).toString(16));
                            log("    flags:        0x" + Memory.readU64(this.ioc_data_address.add(32)).toString(16));
                            break;
                        case 1:
                            log("  write -> KBASE_FUNC_MEM_IMPORT:");
                            log("    phandle: 0x" + Memory.readU32(this.ioc_data_address.add(8)).toString(16));
                            log("    type:    0x" + Memory.readU32(this.ioc_data_address.add(12)).toString(16));
                            log("    padding: 0x" + Memory.readU32(this.ioc_data_address.add(16)).toString(16));
                            log("    flags:   0x" + Memory.readU64(this.ioc_data_address.add(20)).toString(16));
                            break;
                        case 2:
                            log("  write -> KBASE_FUNC_MEM_COMMIT:");
                            log("    gpu_addr: 0x" + Memory.readU64(this.ioc_data_address.add(8)).toString(16));
                            log("    pages:    0x" + Memory.readU64(this.ioc_data_address.add(16)).toString(16));
                            break;
                        case 3:
                            log("  write -> KBASE_FUNC_MEM_QUERY:");
                            log("    gpu_addr: 0x" + Memory.readU64(this.ioc_data_address.add(8)).toString(16));
                            log("    query:    0x" + Memory.readU64(this.ioc_data_address.add(16)).toString(16));
                            break;
                        case 4:
                            log("  write -> KBASE_FUNC_MEM_FREE:");
                            log("    gpu_addr: 0x" + Memory.readU64(this.ioc_data_address.add(8)).toString(16));
                            break;
                        case 5:
                            log("  write -> KBASE_FUNC_MEM_FLAGS_CHANGE:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 6:
                            log("  write -> KBASE_FUNC_MEM_ALIAS:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 7:
                            log("  write -> KBASE_FUNC_JOB_SUBMIT_UK6:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 8:
                            log("  write -> KBASE_FUNC_SYNC:");
                            log("    mem_handle: 0x" + Memory.readU64(this.ioc_data_address.add(8)).toString(16));
                            log("    user_addr:  0x" + Memory.readU64(this.ioc_data_address.add(16)).toString(16));
                            log("    size:       0x" + Memory.readU64(this.ioc_data_address.add(24)).toString(16));
                            log("    type:       0x" + Memory.readU8(this.ioc_data_address.add(32)).toString(16));
                            break;
                        case 9:
                            log("  write -> KBASE_FUNC_POST_TERM:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 10:
                            log("  write -> KBASE_FUNC_HWCNT_SETUP:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 11:
                            log("  write -> KBASE_FUNC_HWCNT_DUMP:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 12:
                            log("  write -> KBASE_FUNC_HWCNT_CLEAR:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 14:
                            log("  write -> KBASE_FUNC_GPU_PROPS_REG_DUMP:");
                            break;
                        case 15:
                            log("  write -> KBASE_FUNC_FIND_CPU_OFFSET:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 16:
                            log("  write -> KBASE_FUNC_GET_VERSION:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 17:
                            log("  write -> KBASE_FUNC_EXT_BUFFER_LOCK:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 18:
                            log("  write -> KBASE_FUNC_SET_FLAGS:");
                            log("    Flags: 0x" + Memory.readU32(this.ioc_data_address.add(8)).toString(16));
                            break;
                        case 19:
                            log("  write -> KBASE_FUNC_SET_TEST_DATA:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 20:
                            log("  write -> KBASE_FUNC_INJECT_ERROR:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 21:
                            log("  write -> KBASE_FUNC_MODEL_CONTROL:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 22:
                            log("  write -> KBASE_FUNC_KEEP_GPU_POWERED:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 23:
                            log("  write -> KBASE_FUNC_FENCE_VALIDATE:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 24:
                            log("  write -> KBASE_FUNC_STREAM_CREATE:");
                            log("    name: " + Memory.readCString(this.ioc_data_address.add(8), 32));
                            break;
                        case 25:
                            log("  write -> KBASE_FUNC_GET_PROFILING_CONTROLS:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 26:
                            log("  write -> KBASE_FUNC_SET_PROFILING_CONTROLS:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 27:
                            log("  write -> KBASE_FUNC_DEBUGFS_MEM_PROFILE_ADD:");
                            log("    len: 0x" + Memory.readU32(this.ioc_data_address.add(8)).toString(16));
                            log("    buf: 0x" + Memory.readU32(this.ioc_data_address.add(12)).toString(16));
                            break;
                        case 28:
                            log("  write -> KBASE_FUNC_JOB_SUBMIT:");
                            log("    addr:     0x" + Memory.readU32(this.ioc_data_address.add(8)).toString(16));
                            log("    nr_atoms: 0x" + Memory.readU32(this.ioc_data_address.add(12)).toString(16));
                            log("    stride:   0x" + Memory.readU32(this.ioc_data_address.add(16)).toString(16));
                            break;
                        case 29:
                            log("  write -> KBASE_FUNC_DISJOINT_QUERY:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 31:
                            log("  write -> KBASE_FUNC_GET_CONTEXT_ID:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 32:
                            log("  write -> KBASE_FUNC_TLSTREAM_ACQUIRE:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 33:
                            log("  write -> KBASE_FUNC_TLSTREAM_TEST:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 34:
                            log("  write -> KBASE_FUNC_TLSTREAM_STATS:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 35:
                            log("  write -> KBASE_FUNC_TLSTREAM_FLUSH:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 36:
                            log("  write -> KBASE_FUNC_HWCNT_READER_SETUP:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 37:
                            log("  write -> KBASE_FUNC_SET_PRFCNT_VALUES:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 38:
                            log("  write -> KBASE_FUNC_SOFT_EVENT_UPDATE:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 39:
                            log("  write -> KBASE_FUNC_MEM_JIT_INIT:");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        default:
                            log("UNKNOWN (" + this.uk_id + "):");
                            log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                    }
                } else {
                    log("UNKNOWN (" + this.uk_id + "):");
                    log("  write -> \n" + hexdump(ioc_data, {header: false, ansi: false}));
                }
            }
        }
    },

    /**
     * Called synchronously when about to return from ioctl.
     *
     * See onEnter for details.
     *
     * @this {object} - Object allowing you to access state stored in onEnter.
     * @param {function} log - Call this function with a string to be presented to the user.
     * @param {NativePointer} retval - Return value represented as a NativePointer object.
     * @param {object} state - Object allowing you to keep state across function calls.
     */
    onLeave: function (log, retval, state) {
        if (this.file.indexOf("/dev/mali") > -1) {
            if ((this.ioc_dir === "_IOWR") || (this.ioc_dir === "_IOR")) {
                ioc_data = Memory.readByteArray(this.ioc_data_address, this.ioc_size);
                retval = Memory.readU32(this.ioc_data_address);
                if (this.uk_id === 0) {
                    log("  read  <- UKP_FUNC_ID_CHECK_VERSION:");
                    log("    Major version: 0x" + Memory.readU16(this.ioc_data_address.add(8)).toString(16));
                    log("    Minor version: 0x" + Memory.readU16(this.ioc_data_address.add(10)).toString(16));
                    log("    Retval:        0x" + retval.toString(16));
                } else if (this.uk_id >= 512) {
                    switch(this.uk_id - 512) {
                        case 0:
                            log("  read  <- KBASE_FUNC_MEM_ALLOC:");
                            log("    flags:        0x" + Memory.readU64(this.ioc_data_address.add(32)).toString(16));
                            log("    gpu_va:       0x" + Memory.readU64(this.ioc_data_address.add(40)).toString(16));
                            log("    va_alignment: 0x" + Memory.readU16(this.ioc_data_address.add(48)).toString(16));
                            log("    Retval:       0x" + retval.toString(16));
                            break;
                        case 1:
                            log("  read  <- KBASE_FUNC_MEM_IMPORT:");
                            log("    flags:    0x" + Memory.readU64(this.ioc_data_address.add(20)).toString(16));
                            log("    gpu_va:   0x" + Memory.readU64(this.ioc_data_address.add(28)).toString(16));
                            log("    va_pages: 0x" + Memory.readU64(this.ioc_data_address.add(36)).toString(16));
                            log("    Retval:   0x" + retval.toString(16));
                            break;
                        case 2:
                            log("  read  <- KBASE_FUNC_MEM_COMMIT:");
                            log("    result_subcode: 0x" + Memory.readU32(this.ioc_data_address.add(24)).toString(16));
                            log("    Retval:         0x" + retval.toString(16));
                            break;
                        case 3:
                            log("  read  <- KBASE_FUNC_MEM_QUERY:");
                            log("    value: 0x" + Memory.readU64(this.ioc_data_address.add(24)).toString(16));
                            log("    Retval:   0x" + retval.toString(16));
                            break;
                        case 4:
                            log("  read  <- KBASE_FUNC_MEM_FREE:");
                            log("    Retval:   0x" + retval.toString(16));
                            break;
                        case 5:
                            log("  read  <- KBASE_FUNC_MEM_FLAGS_CHANGE:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 6:
                            log("  read  <- KBASE_FUNC_MEM_ALIAS:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 7:
                            log("  read  <- KBASE_FUNC_JOB_SUBMIT_UK6:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 8:
                            log("  read  <- KBASE_FUNC_SYNC:");
                            log("    Retval: 0x" + retval.toString(16));
                            break;
                        case 9:
                            log("  read  <- KBASE_FUNC_POST_TERM:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 10:
                            log("  read  <- KBASE_FUNC_HWCNT_SETUP:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 11:
                            log("  read  <- KBASE_FUNC_HWCNT_DUMP:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 12:
                            log("  read  <- KBASE_FUNC_HWCNT_CLEAR:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 14:
                            log("  read  <- KBASE_FUNC_GPU_PROPS_REG_DUMP:");
                            log("    core_props:");
                            log("      product_id:                0x" + Memory.readU32(this.ioc_data_address.add(8)).toString(16));
                            log("      version_status:            0x" + Memory.readU16(this.ioc_data_address.add(12)).toString(16));
                            log("      minor_revision:            0x" + Memory.readU16(this.ioc_data_address.add(14)).toString(16));
                            log("      major_revision:            0x" + Memory.readU16(this.ioc_data_address.add(16)).toString(16));
                            log("      gpu_speed_mhz:             " + Memory.readU32(this.ioc_data_address.add(20)).toString(10));
                            log("      gpu_freq_khz_max:          " + Memory.readU32(this.ioc_data_address.add(24)).toString(10));
                            log("      gpu_freq_khz_min:          " + Memory.readU32(this.ioc_data_address.add(28)).toString(10));
                            log("      log2_program_counter_size: 0x" + Memory.readU32(this.ioc_data_address.add(32)).toString(16));
                            log("      texture_features[0]:       0x" + Memory.readU32(this.ioc_data_address.add(36)).toString(16));
                            log("      texture_features[1]:       0x" + Memory.readU32(this.ioc_data_address.add(40)).toString(16));
                            log("      texture_features[2]:       0x" + Memory.readU32(this.ioc_data_address.add(44)).toString(16));
                            log("      gpu_available_memory_size: 0x" + Memory.readU64(this.ioc_data_address.add(48)).toString(16));
                            log("    l2_props:");
                            log("      log2_line_size:            0x" + Memory.readU8(this.ioc_data_address.add(56)).toString(16));
                            log("      log2_cache_size:           0x" + Memory.readU8(this.ioc_data_address.add(57)).toString(16));
                            log("      num_l2_slices:             0x" + Memory.readU8(this.ioc_data_address.add(58)).toString(16));
                            // +5 bytes padding, start at 64
                            // +8 unused_1 (72)
                            log("    tiler_props:");
                            log("      bin_size_bytes:            0x" + Memory.readU32(this.ioc_data_address.add(72)).toString(16));
                            log("      max_active_levels:         0x" + Memory.readU32(this.ioc_data_address.add(76)).toString(16));
                            log("    thread_props:");
                            log("      max_threads:               0x" + Memory.readU32(this.ioc_data_address.add(80)).toString(16));
                            log("      max_workgroup_size:        0x" + Memory.readU32(this.ioc_data_address.add(84)).toString(16));
                            log("      max_barrier_size:          0x" + Memory.readU32(this.ioc_data_address.add(88)).toString(16));
                            log("      max_registers:             0x" + Memory.readU16(this.ioc_data_address.add(92)).toString(16));
                            log("      max_task_queue:            0x" + Memory.readU8(this.ioc_data_address.add(94)).toString(16));
                            log("      max_thread_group_split:    0x" + Memory.readU8(this.ioc_data_address.add(95)).toString(16));
                            log("      impl_tech:                 0x" + Memory.readU8(this.ioc_data_address.add(96)).toString(16));
                            // +7 bytes padding, start at 104
                            log("    raw_props:");
                            log("      shader_present:            0x" + Memory.readU64(this.ioc_data_address.add(104)).toString(16));
                            log("      tiler_present:             0x" + Memory.readU64(this.ioc_data_address.add(112)).toString(16));
                            log("      l2_present:                0x" + Memory.readU64(this.ioc_data_address.add(120)).toString(16));
                            log("      l2_features:               0x" + Memory.readU32(this.ioc_data_address.add(136)).toString(16));
                            log("      suspend_size:              0x" + Memory.readU32(this.ioc_data_address.add(140)).toString(16));
                            log("      mem_features:              0x" + Memory.readU32(this.ioc_data_address.add(144)).toString(16));
                            log("      mmu_features:              0x" + Memory.readU32(this.ioc_data_address.add(148)).toString(16));
                            log("      as_present:                0x" + Memory.readU32(this.ioc_data_address.add(152)).toString(16));
                            log("      js_present:                0x" + Memory.readU32(this.ioc_data_address.add(156)).toString(16));
                            log("      js_features[0]:            0x" + Memory.readU32(this.ioc_data_address.add(160)).toString(16));
                            log("      js_features[1]:            0x" + Memory.readU32(this.ioc_data_address.add(164)).toString(16));
                            log("      js_features[2]:            0x" + Memory.readU32(this.ioc_data_address.add(168)).toString(16));
                            log("      js_features[3]:            0x" + Memory.readU32(this.ioc_data_address.add(172)).toString(16));
                            log("      js_features[4]:            0x" + Memory.readU32(this.ioc_data_address.add(176)).toString(16));
                            log("      js_features[5]:            0x" + Memory.readU32(this.ioc_data_address.add(180)).toString(16));
                            log("      js_features[6]:            0x" + Memory.readU32(this.ioc_data_address.add(184)).toString(16));
                            log("      js_features[7]:            0x" + Memory.readU32(this.ioc_data_address.add(188)).toString(16));
                            log("      js_features[8]:            0x" + Memory.readU32(this.ioc_data_address.add(192)).toString(16));
                            log("      js_features[9]:            0x" + Memory.readU32(this.ioc_data_address.add(196)).toString(16));
                            log("      js_features[10]:           0x" + Memory.readU32(this.ioc_data_address.add(200)).toString(16));
                            log("      js_features[11]:           0x" + Memory.readU32(this.ioc_data_address.add(204)).toString(16));
                            log("      js_features[12]:           0x" + Memory.readU32(this.ioc_data_address.add(208)).toString(16));
                            log("      js_features[13]:           0x" + Memory.readU32(this.ioc_data_address.add(212)).toString(16));
                            log("      js_features[14]:           0x" + Memory.readU32(this.ioc_data_address.add(216)).toString(16));
                            log("      js_features[15]:           0x" + Memory.readU32(this.ioc_data_address.add(220)).toString(16));
                            log("      tiler_features:            0x" + Memory.readU32(this.ioc_data_address.add(224)).toString(16));
                            log("      texture_features[0]:       0x" + Memory.readU32(this.ioc_data_address.add(228)).toString(16));
                            log("      texture_features[1]:       0x" + Memory.readU32(this.ioc_data_address.add(232)).toString(16));
                            log("      texture_features[2]:       0x" + Memory.readU32(this.ioc_data_address.add(236)).toString(16));
                            log("      gpu_id:                    0x" + Memory.readU32(this.ioc_data_address.add(240)).toString(16));
                            log("      thread_max_threads:        0x" + Memory.readU32(this.ioc_data_address.add(244)).toString(16));
                            log("      thread_max_workgroup_size: 0x" + Memory.readU32(this.ioc_data_address.add(248)).toString(16));
                            log("      thread_max_barrier_size:   0x" + Memory.readU32(this.ioc_data_address.add(252)).toString(16));
                            log("      thread_features:           0x" + Memory.readU32(this.ioc_data_address.add(256)).toString(16));
                            log("      coherency_mode:            0x" + Memory.readU32(this.ioc_data_address.add(260)).toString(16));
                            log("    coherency_info:");
                            log("      num_groups:                0x" + Memory.readU32(this.ioc_data_address.add(264)).toString(16));
                            log("      num_core_groups:           0x" + Memory.readU32(this.ioc_data_address.add(268)).toString(16));
                            log("      coherency:                 0x" + Memory.readU32(this.ioc_data_address.add(272)).toString(16));
                            log("      padding:                   0x" + Memory.readU32(this.ioc_data_address.add(276)).toString(16));
                            log("      group[0]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(280)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(288)).toString(16));
                            // +6 bytes padding
                            log("      group[1]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(296)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(304)).toString(16));
                            // +6 bytes padding
                            log("      group[2]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(312)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(320)).toString(16));
                            // +6 bytes padding
                            log("      group[3]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(328)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(336)).toString(16));
                            // +6 bytes padding
                            log("      group[4]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(344)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(352)).toString(16));
                            // +6 bytes padding
                            log("      group[5]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(360)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(368)).toString(16));
                            // +6 bytes padding
                            log("      group[6]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(376)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(384)).toString(16));
                            // +6 bytes padding
                            log("      group[7]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(392)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(400)).toString(16));
                            // +6 bytes padding
                            log("      group[8]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(408)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(416)).toString(16));
                            // +6 bytes padding
                            log("      group[9]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(424)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(432)).toString(16));
                            // +6 bytes padding
                            log("      group[10]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(440)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(448)).toString(16));
                            // +6 bytes padding
                            log("      group[11]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(456)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(464)).toString(16));
                            // +6 bytes padding
                            log("      group[12]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(472)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(480)).toString(16));
                            // +6 bytes padding
                            log("      group[13]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(488)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(496)).toString(16));
                            // +6 bytes padding
                            log("      group[14]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(504)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(512)).toString(16));
                            // +6 bytes padding
                            log("      group[15]:");
                            log("        core_mask:               0x" + Memory.readU64(this.ioc_data_address.add(520)).toString(16));
                            log("        num_cores:               0x" + Memory.readU16(this.ioc_data_address.add(528)).toString(16));
                            // +6 bytes padding
                            log("    Retval: 0x" + retval.toString(16));
                            break;
                        case 15:
                            log("  read  <- KBASE_FUNC_FIND_CPU_OFFSET:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 16:
                            log("  read  <- KBASE_FUNC_GET_VERSION:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 17:
                            log("  read  <- KBASE_FUNC_EXT_BUFFER_LOCK:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 18:
                            log("  read  <- KBASE_FUNC_SET_FLAGS:");
                            log("    Retval: 0x" + retval.toString(16));
                            break;
                        case 19:
                            log("  read  <- KBASE_FUNC_SET_TEST_DATA:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 20:
                            log("  read  <- KBASE_FUNC_INJECT_ERROR:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 21:
                            log("  read  <- KBASE_FUNC_MODEL_CONTROL:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 22:
                            log("  read  <- KBASE_FUNC_KEEP_GPU_POWERED:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 23:
                            log("  read  <- KBASE_FUNC_FENCE_VALIDATE:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 24:
                            log("  read  <- KBASE_FUNC_STREAM_CREATE:");
                            log("    fd: " + Memory.readS32(this.ioc_data_address.add(40)).toString(10));
                            log("    Retval: 0x" + retval.toString(16));
                            break;
                        case 25:
                            log("  read  <- KBASE_FUNC_GET_PROFILING_CONTROLS:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 26:
                            log("  read  <- KBASE_FUNC_SET_PROFILING_CONTROLS:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 27:
                            log("  read  <- KBASE_FUNC_DEBUGFS_MEM_PROFILE_ADD:");
                            log("    Retval: 0x" + retval.toString(16));
                            break;
                        case 28:
                            log("  read  <- KBASE_FUNC_JOB_SUBMIT:");
                            log("    Retval: 0x" + retval.toString(16));
                            break;
                        case 29:
                            log("  read  <- KBASE_FUNC_DISJOINT_QUERY:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 31:
                            log("  read  <- KBASE_FUNC_GET_CONTEXT_ID:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 32:
                            log("  read  <- KBASE_FUNC_TLSTREAM_ACQUIRE:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 33:
                            log("  read  <- KBASE_FUNC_TLSTREAM_TEST:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 34:
                            log("  read  <- KBASE_FUNC_TLSTREAM_STATS:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 35:
                            log("  read  <- KBASE_FUNC_TLSTREAM_FLUSH:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 36:
                            log("  read  <- KBASE_FUNC_HWCNT_READER_SETUP:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 37:
                            log("  read  <- KBASE_FUNC_SET_PRFCNT_VALUES:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 38:
                            log("  read  <- KBASE_FUNC_SOFT_EVENT_UPDATE:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        case 39:
                            log("  read  <- KBASE_FUNC_MEM_JIT_INIT:");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                            break;
                        default:
                            log("UNKNOWN (" + this.uk_id + "):");
                            log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                    }
                } else {
                    log("UNKNOWN (" + this.uk_id + "):");
                    log("  read  <- \n" + hexdump(ioc_data, {header: false, ansi: false}));
                }
            }
        }
    }
}
