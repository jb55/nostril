
#ifndef CURSOR_H
#define CURSOR_H

#include <stdio.h>
#include <assert.h>
#include <string.h>

#ifdef _MSC_VER
# pragma warning(push)
# pragma warning(disable: 4005) 
# pragma warning(disable: 4477) 
#endif

#ifdef _MSC_VER
#define unlikely
#define likely
#else
#define unlikely(x) __builtin_expect((x),0)
#define likely(x)   __builtin_expect((x),1)
#endif 

struct cursor {
	unsigned char *start;
	unsigned char *p;
	unsigned char *end;
};

struct array {
	struct cursor cur;
	unsigned int elem_size;
};

static inline void reset_cursor(struct cursor *cursor)
{
	cursor->p = cursor->start;
}

static inline void wipe_cursor(struct cursor *cursor)
{
	reset_cursor(cursor);
	memset(cursor->start, 0, cursor->end - cursor->start);
}

static inline void make_cursor(unsigned char *start, unsigned char *end, struct cursor *cursor)
{
	cursor->start = start;
	cursor->p = start;
	cursor->end = end;
}

static inline void make_array(struct array *a, unsigned char* start, unsigned char *end, unsigned int elem_size)
{
	make_cursor(start, end, &a->cur);
	a->elem_size = elem_size;
}

static inline int cursor_eof(struct cursor *c)
{
	return c->p == c->end;
}

static inline void *cursor_malloc(struct cursor *mem, unsigned long size)
{
	void *ret;

	if (mem->p + size > mem->end) {
		return NULL;
	}

	ret = mem->p;
	mem->p += size;

	return ret;
}

static inline void *cursor_alloc(struct cursor *mem, unsigned long size)
{
	void *ret;
	if (!(ret = cursor_malloc(mem, size))) {
		return 0;
	}

	memset(ret, 0, size);
	return ret;
}

static inline int cursor_slice(struct cursor *mem, struct cursor *slice, size_t size)
{
	unsigned char *p;
	if (!(p = cursor_alloc(mem, size))) {
		return 0;
	}
	make_cursor(p, mem->p, slice);
	return 1;
}


static inline void copy_cursor(struct cursor *src, struct cursor *dest)
{
	dest->start = src->start;
	dest->p = src->p;
	dest->end = src->end;
}

static inline int pull_byte(struct cursor *cursor, unsigned char *c)
{
	if (unlikely(cursor->p + 1 > cursor->end))
		return 0;

	*c = *cursor->p;
	cursor->p++;

	return 1;
}

static inline int cursor_pull_c_str(struct cursor *cursor, const char **str)
{
	*str = (const char*)cursor->p;

	for (; cursor->p < cursor->end; cursor->p++) {
		if (*cursor->p == 0) {
			cursor->p++;
			return 1;
		}
	}

	return 0;
}


static inline int cursor_push_byte(struct cursor *cursor, unsigned char c)
{
	if (unlikely(cursor->p + 1 > cursor->end)) {
		return 0;
	}

	*cursor->p = c;
	cursor->p++;

	return 1;
}

static inline int cursor_pull(struct cursor *cursor, unsigned char *data, int len)
{
	if (unlikely(cursor->p + len > cursor->end)) {
		return 0;
	}

	memcpy(data, cursor->p, len);
	cursor->p += len;

	return 1;
}

static inline int pull_data_into_cursor(struct cursor *cursor,
			  struct cursor *dest,
			  unsigned char **data,
			  int len)
{
	int ok;

	if (unlikely(dest->p + len > dest->end)) {
		printf("not enough room in dest buffer\n");
		return 0;
	}

	ok = cursor_pull(cursor, dest->p, len);
	if (!ok) return 0;

	*data = dest->p;
	dest->p += len;

	return 1;
}

static inline int cursor_dropn(struct cursor *cur, int size, int n)
{
	if (n == 0)
		return 1;

	if (unlikely(cur->p - size*n < cur->start)) {
		return 0;
	}

	cur->p -= size*n;
	return 1;
}

static inline int cursor_drop(struct cursor *cur, int size)
{
	return cursor_dropn(cur, size, 1);
}

static inline unsigned char *cursor_topn(struct cursor *cur, int len, int n)
{
	n += 1;
	if (unlikely(cur->p - len*n < cur->start)) {
		return NULL;
	}
	return cur->p - len*n;
}

static inline unsigned char *cursor_top(struct cursor *cur, int len)
{
	if (unlikely(cur->p - len < cur->start)) {
		return NULL;
	}
	return cur->p - len;
}

static inline int cursor_top_int(struct cursor *cur, int *i)
{
	unsigned char *p;
	if (unlikely(!(p = cursor_top(cur, sizeof(*i))))) {
		return 0;
	}
	*i = *((int*)p);
	return 1;
}

static inline int cursor_pop(struct cursor *cur, unsigned char *data, int len)
{
	if (unlikely(cur->p - len < cur->start)) {
		return 0;
	}

	cur->p -= len;
	memcpy(data, cur->p, len);

	return 1;
}

static inline int cursor_push(struct cursor *cursor, unsigned char *data, int len)
{
	if (unlikely(cursor->p + len >= cursor->end)) {
		return 0;
	}

	if (cursor->p != data)
		memcpy(cursor->p, data, len);

	cursor->p += len;

	return 1;
}

static inline int cursor_push_int(struct cursor *cursor, int i)
{
	return cursor_push(cursor, (unsigned char*)&i, sizeof(i));
}

static inline int cursor_len(struct cursor *cursor)
{
	return cursor->p - cursor->start;
}

static inline size_t cursor_count(struct cursor *cursor, size_t elem_size)
{
	return cursor_len(cursor)/elem_size;
}

static inline int cursor_pull_int(struct cursor *cursor, int *i)
{
	return cursor_pull(cursor, (unsigned char*)i, sizeof(*i));
}

static inline int cursor_push_u16(struct cursor *cursor, unsigned short i)
{
	return cursor_push(cursor, (unsigned char*)&i, sizeof(i));
}

static inline void *index_cursor(struct cursor *cursor, unsigned int index, int elem_size)
{
	unsigned char *p;
	p = &cursor->start[elem_size * index];

	if (unlikely(p >= cursor->end))
		return NULL;

	return (void*)p;
}


static inline int push_sized_str(struct cursor *cursor, const char *str, int len)
{
	return cursor_push(cursor, (unsigned char*)str, len);
}

static inline int cursor_push_str(struct cursor *cursor, const char *str)
{
	return cursor_push(cursor, (unsigned char*)str, strlen(str));
}

static inline int cursor_push_c_str(struct cursor *cursor, const char *str)
{
	return cursor_push_str(cursor, str) && cursor_push_byte(cursor, 0);
}

static inline int cursor_remaining_capacity(struct cursor *cursor)
{
	return cursor->end - cursor->p;
}


#define max(a,b) ((a) > (b) ? (a) : (b))
static inline void cursor_print_around(struct cursor *cur, int range)
{
	unsigned char *c;

	printf("[%ld/%ld]\n", cur->p - cur->start, cur->end - cur->start);

	c = max(cur->p - range, cur->start);
	for (; c < cur->end && c < (cur->p + range); c++) {
		printf("%02x", *c);
	}
	printf("\n");

	c = max(cur->p - range, cur->start);
	for (; c < cur->end && c < (cur->p + range); c++) {
		if (c == cur->p) {
			printf("^");
			continue;
		}
		printf("  ");
	}
	printf("\n");
}
#undef max

#endif
