/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM filemap

#if !defined(_TRACE_FILEMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_FILEMAP_H

#include <linux/types.h>
#include <linux/tracepoint.h>
#include <linux/mm.h>
#include <linux/memcontrol.h>
#include <linux/device.h>
#include <linux/kdev_t.h>
#include <linux/errseq.h>

DECLARE_EVENT_CLASS(mm_filemap_op_page_cache,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(u64, i_ino)
		__field(unsigned long, pfn)
		__field(unsigned long, index)
		__field(dev_t, s_dev)
		__field(unsigned char, order)
	),

	TP_fast_assign(
		__entry->pfn = folio_pfn(folio);
		__entry->i_ino = folio->mapping->host->i_ino;
		__entry->index = folio->index;
		if (folio->mapping->host->i_sb)
			__entry->s_dev = folio->mapping->host->i_sb->s_dev;
		else
			__entry->s_dev = folio->mapping->host->i_rdev;
		__entry->order = folio_order(folio);
	),

	TP_printk("dev %d:%d ino %llx pfn=0x%lx ofs=%lu order=%u",
		MAJOR(__entry->s_dev), MINOR(__entry->s_dev),
		__entry->i_ino,
		__entry->pfn,
		__entry->index << PAGE_SHIFT,
		__entry->order)
);

DEFINE_EVENT(mm_filemap_op_page_cache, mm_filemap_delete_from_page_cache,
	TP_PROTO(struct folio *folio),
	TP_ARGS(folio)
	);

DEFINE_EVENT(mm_filemap_op_page_cache, mm_filemap_add_to_page_cache,
	TP_PROTO(struct folio *folio),
	TP_ARGS(folio)
	);

DEFINE_EVENT(mm_filemap_op_page_cache, mm_filemap_add_to_page_cache_prefetch,
	TP_PROTO(struct folio *folio),
	TP_ARGS(folio)
	);

DEFINE_EVENT(mm_filemap_op_page_cache, mm_cache_ext_prefetch_hit,
	TP_PROTO(struct folio *folio),
	TP_ARGS(folio)
	);

DEFINE_EVENT(mm_filemap_op_page_cache, mm_cache_ext_prefetch_miss,
	TP_PROTO(struct folio *folio),
	TP_ARGS(folio)
	);

DECLARE_EVENT_CLASS(mm_filemap_op_page_cache_range,

	TP_PROTO(
		struct address_space *mapping,
		pgoff_t index,
		pgoff_t last_index
	),

	TP_ARGS(mapping, index, last_index),

	TP_STRUCT__entry(
		__field(u64, i_ino)
		__field(dev_t, s_dev)
		__field(unsigned long, index)
		__field(unsigned long, last_index)
	),

	TP_fast_assign(
		__entry->i_ino = mapping->host->i_ino;
		if (mapping->host->i_sb)
			__entry->s_dev =
				mapping->host->i_sb->s_dev;
		else
			__entry->s_dev = mapping->host->i_rdev;
		__entry->index = index;
		__entry->last_index = last_index;
	),

	TP_printk(
		"dev=%d:%d ino=%llx ofs=%lld-%lld",
		MAJOR(__entry->s_dev),
		MINOR(__entry->s_dev), __entry->i_ino,
		((loff_t)__entry->index) << PAGE_SHIFT,
		((((loff_t)__entry->last_index + 1) << PAGE_SHIFT) - 1)
	)
);

DEFINE_EVENT(mm_filemap_op_page_cache_range, mm_filemap_get_pages,
	TP_PROTO(
		struct address_space *mapping,
		pgoff_t index,
		pgoff_t last_index
	),
	TP_ARGS(mapping, index, last_index)
);

DEFINE_EVENT(mm_filemap_op_page_cache_range, mm_filemap_map_pages,
	TP_PROTO(
		struct address_space *mapping,
		pgoff_t index,
		pgoff_t last_index
	),
	TP_ARGS(mapping, index, last_index)
);

TRACE_EVENT(mm_cache_ext_readahead_decision,
	TP_PROTO(struct address_space *mapping, pgoff_t index, size_t size,
		 s32 decision, u32 ra_pages, u32 prealloc_pages, u32 dropbehind),
	TP_ARGS(mapping, index, size, decision, ra_pages, prealloc_pages, dropbehind),
	TP_STRUCT__entry(
		__field(unsigned long, i_ino)
		__field(dev_t, s_dev)
		__field(unsigned long, index)
		__field(size_t, size)
		__field(s32, decision)
		__field(u32, ra_pages)
		__field(u32, prealloc_pages)
		__field(u32, dropbehind)
	),
	TP_fast_assign(
		__entry->i_ino = mapping->host->i_ino;
		if (mapping->host->i_sb)
			__entry->s_dev = mapping->host->i_sb->s_dev;
		else
			__entry->s_dev = mapping->host->i_rdev;
		__entry->index = index;
		__entry->size = size;
		__entry->decision = decision;
		__entry->ra_pages = ra_pages;
		__entry->prealloc_pages = prealloc_pages;
		__entry->dropbehind = dropbehind;
	),
	TP_printk("dev=%d:%d ino=%lx ofs=%lu size=%zu decision=%d ra_pages=%u prealloc_pages=%u dropbehind=%u",
		MAJOR(__entry->s_dev), MINOR(__entry->s_dev),
		__entry->i_ino,
		__entry->index << PAGE_SHIFT,
		__entry->size,
		__entry->decision,
		__entry->ra_pages,
		__entry->prealloc_pages,
		__entry->dropbehind)
);

TRACE_EVENT(mm_filemap_fault,
	TP_PROTO(struct address_space *mapping, pgoff_t index),

	TP_ARGS(mapping, index),

	TP_STRUCT__entry(
		__field(u64, i_ino)
		__field(dev_t, s_dev)
		__field(unsigned long, index)
	),

	TP_fast_assign(
		__entry->i_ino = mapping->host->i_ino;
		if (mapping->host->i_sb)
			__entry->s_dev =
				mapping->host->i_sb->s_dev;
		else
			__entry->s_dev = mapping->host->i_rdev;
		__entry->index = index;
	),

	TP_printk(
		"dev=%d:%d ino=%llx ofs=%lld",
		MAJOR(__entry->s_dev),
		MINOR(__entry->s_dev), __entry->i_ino,
		((loff_t)__entry->index) << PAGE_SHIFT
	)
);

TRACE_EVENT(filemap_set_wb_err,
		TP_PROTO(struct address_space *mapping, errseq_t eseq),

		TP_ARGS(mapping, eseq),

		TP_STRUCT__entry(
			__field(u64, i_ino)
			__field(dev_t, s_dev)
			__field(errseq_t, errseq)
		),

		TP_fast_assign(
			__entry->i_ino = mapping->host->i_ino;
			__entry->errseq = eseq;
			if (mapping->host->i_sb)
				__entry->s_dev = mapping->host->i_sb->s_dev;
			else
				__entry->s_dev = mapping->host->i_rdev;
		),

		TP_printk("dev=%d:%d ino=0x%llx errseq=0x%x",
			MAJOR(__entry->s_dev), MINOR(__entry->s_dev),
			__entry->i_ino, __entry->errseq)
);

TRACE_EVENT(file_check_and_advance_wb_err,
		TP_PROTO(struct file *file, errseq_t old),

		TP_ARGS(file, old),

		TP_STRUCT__entry(
			__field(u64, i_ino)
			__field(struct file *, file)
			__field(dev_t, s_dev)
			__field(errseq_t, old)
			__field(errseq_t, new)
		),

		TP_fast_assign(
			__entry->file = file;
			__entry->i_ino = file->f_mapping->host->i_ino;
			if (file->f_mapping->host->i_sb)
				__entry->s_dev =
					file->f_mapping->host->i_sb->s_dev;
			else
				__entry->s_dev =
					file->f_mapping->host->i_rdev;
			__entry->old = old;
			__entry->new = file->f_wb_err;
		),

		TP_printk("file=%p dev=%d:%d ino=0x%llx old=0x%x new=0x%x",
			__entry->file, MAJOR(__entry->s_dev),
			MINOR(__entry->s_dev), __entry->i_ino, __entry->old,
			__entry->new)
);

TRACE_EVENT(mm_cache_ext_attach,
	TP_PROTO(void *memcg, int ret),
	TP_ARGS(memcg, ret),
	TP_STRUCT__entry(
		__field(void *, memcg)
		__field(int, ret)
	),
	TP_fast_assign(
		__entry->memcg = memcg;
		__entry->ret = ret;
	),
	TP_printk("memcg=%p ret=%d", __entry->memcg, __entry->ret)
);

TRACE_EVENT(mm_cache_ext_detach,
	TP_PROTO(void *memcg),
	TP_ARGS(memcg),
	TP_STRUCT__entry(
		__field(void *, memcg)
	),
	TP_fast_assign(
		__entry->memcg = memcg;
	),
	TP_printk("memcg=%p", __entry->memcg)
);

TRACE_EVENT(mm_cache_ext_list_op,
	TP_PROTO(const char *op, u64 handle, int ret),
	TP_ARGS(op, handle, ret),
	TP_STRUCT__entry(
		__string(op, op)
		__field(u64, handle)
		__field(int, ret)
	),
	TP_fast_assign(
		__assign_str(op);
		__entry->handle = handle;
		__entry->ret = ret;
	),
	TP_printk("op=%s handle=%llu ret=%d",
		  __get_str(op), __entry->handle, __entry->ret)
);

TRACE_EVENT(mm_cache_ext_prealloc,
	TP_PROTO(struct file *file, unsigned long index, unsigned long nr_pages,
		 bool dropbehind, int ret),
	TP_ARGS(file, index, nr_pages, dropbehind, ret),
	TP_STRUCT__entry(
		__field(struct file *, file)
		__field(unsigned long, index)
		__field(unsigned long, nr_pages)
		__field(bool, dropbehind)
		__field(int, ret)
	),
	TP_fast_assign(
		__entry->file = file;
		__entry->index = index;
		__entry->nr_pages = nr_pages;
		__entry->dropbehind = dropbehind;
		__entry->ret = ret;
	),
	TP_printk("file=%p index=%lu nr_pages=%lu dropbehind=%d ret=%d",
		  __entry->file, __entry->index, __entry->nr_pages,
		  __entry->dropbehind, __entry->ret)
);
#endif /* _TRACE_FILEMAP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
