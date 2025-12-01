#pragma once

/* Keep LVGL’s builtin allocator, but expand its pool from PSRAM */
#define LV_USE_STDLIB_MALLOC    LV_STDLIB_BUILTIN

/* Small initial pool (internal RAM), expand in PSRAM chunks */
#ifndef LV_MEM_SIZE
#define LV_MEM_SIZE (8 * 1024U)                 /* 8 KB initial */
#endif

#ifndef LV_MEM_POOL_EXPAND_SIZE
#define LV_MEM_POOL_EXPAND_SIZE (16 * 1024U)    /* grow by 16 KB */
#endif

/* Tell lv_mem.c how to allocate expansion blocks (only lv_mem.c includes this) */
#ifndef LV_MEM_POOL_INCLUDE
#define LV_MEM_POOL_INCLUDE <esp_heap_caps.h>
#endif

#ifndef LV_MEM_POOL_ALLOC
#define LV_MEM_POOL_ALLOC(sz) heap_caps_malloc((sz), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)
#endif

#ifndef LV_MEM_POOL_FREE
#define LV_MEM_POOL_FREE(p)   heap_caps_free((p))
#endif

/* Don’t predefine an external pool buffer */
#ifndef LV_MEM_ADR
#define LV_MEM_ADR 0
#endif

/* Optional diagnostics */
#ifndef LV_USE_SYSMON
#define LV_USE_SYSMON 1
#endif
#ifndef LV_USE_MEM_MONITOR
#define LV_USE_MEM_MONITOR 1
#endif