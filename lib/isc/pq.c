#include <assert.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/random.h>
#include <isc/refcount.h>

/* PUBLIC */

typedef struct isc_pq isc_pq_t;

bool
Insert(isc_pq_t *pq, uint32_t key, void *value);
void *
DeleteMin(isc_pq_t *pq);

/* PRIVATE */

#define MAXLEVEL 31 /* floor(log2(UINT32_MAX)) */

#define NODE_NEXT(node, level) ((node)->next[level])
#define NODE_PREV(node)	       ((node)->prev)

#define PQ_HEAD(pq) (node_t *)atomic_load(&(pq)->head)
#define PQ_TAIL(pq) (node_t *)atomic_load(&(pq)->tail)

#define COPY_HEAD(pq) copy_node(PQ_HEAD(pq))

#define GET_PREV(pq, prevp, level, key) { \
		node_t *__tmp_node = ScanKey(pq, &prev, i, key); \
		release_node(&__tmp_node);			 \
	}

typedef struct node node_t;

struct isc_pq {
	unsigned int magic;
	isc_mem_t *mctx;
	atomic_uintptr_t head;
	atomic_uintptr_t tail;
	uint32_t maxlevel;
	bool unique;
};

struct node {
	isc_pq_t *pq;
	isc_refcount_t references;
	uint32_t key;
	uint32_t level;
	atomic_uint_fast32_t valid;
	atomic_uintptr_t value;
	atomic_uintptr_t prev;
	atomic_uintptr_t next[];
};

#undef isc_mem_create
#undef isc_mem_destroy
#undef isc_mem_get
#undef isc_mem_put
#undef isc_mem_attach
#undef isc_mem_putanddetach

#define isc_mem_create(mctxp) (void)mctxp;
#define isc_mem_attach(s, t)
#define isc_mem_putanddetach(m, p, s) free(p)
#define isc_mem_put(mctx, node, size) free(node)
#define isc_mem_get(mctx, size) calloc(1, size)
#define isc_mem_detach(mctx)
#define isc_mem_checkdestroyed(f)

node_t *
HelpDelete(isc_pq_t *pq, node_t *node, size_t level);

static void
node_free(void *node0) {
	node_t *node = (node_t *)node0;
	isc_refcount_destroy(&node->references);
	node->references = UINT32_MAX;
	isc_mem_put(node->pq->mctx, node, sizeof(*node) + node->level * sizeof(node->next[0]));
}

static node_t *
node_new(isc_pq_t *pq, size_t level, uint32_t key, void *value) {
	REQUIRE(level > 0);
	REQUIRE(level <= pq->maxlevel);

	node_t *node = isc_mem_get(pq->mctx, sizeof(*node) + level * sizeof(node->next[0]));
	*node = (node_t){ .pq = pq,
			  .level = level,
			  .valid = 0,
			  .key = key };
	atomic_init(&node->valid, 0);
	atomic_init(&node->value, (uintptr_t)value);
	isc_refcount_init(&node->references, 1);
	for (size_t i = 0; i < level; i++) {
		atomic_init(&node->next[i], (uintptr_t)0);
	}
	return (node);
}

#define NODE_MARK UINT64_C(0x01)

#define is_marked(node) ((((uintptr_t)node) & NODE_MARK) == NODE_MARK)
#define get_marked(node) (((uintptr_t)node) | NODE_MARK)
#define get_unmarked(node) (((uintptr_t)node) & ~NODE_MARK)


#define read_node(nodep) _read_node(nodep, __FILE__, __LINE__)
#define copy_node(node) _copy_node(node, __FILE__, __LINE__)
#define release_node(node) _release_node(node, __FILE__, __LINE__)
#define ReadNext(pq, nodep, level) _ReadNext(pq, nodep, level, __FILE__, __LINE__)
#define ScanKey(pq, nodep, level, key) _ScanKey(pq, nodep, level, key, __FILE__, __LINE__)

static node_t *
_read_node(node_t **nodep, char *file, unsigned int line) {
	assert(nodep != NULL);
	node_t *node = *nodep;
	if (node == NULL || is_marked(node)) {
		fprintf(stderr, "%s:%u:%u: read_node: %p\n", file, line, (unsigned int)pthread_self(), (node));
		return NULL;
	}
	if (atomic_load(&node->references) > 100) {
		fprintf(stderr, "%s:%u:%u: READ_NODE: %p->%" PRIxFAST32 "!!!!!!!!\n", file, line, (unsigned int)pthread_self(), node, node->references);
	} else {
		fprintf(stderr, "%s:%u:%u: read_node: %p->%" PRIxFAST32 "\n", file, line, (unsigned int)pthread_self(), node, node->references);
	}
	isc_refcount_increment(&node->references);
	return (node);
}

static node_t *
_copy_node(node_t *node, char *file, unsigned int line) {
	REQUIRE(node != NULL);
	fprintf(stderr, "%s:%u:%u: copy_node: %p->%" PRIxFAST32 "\n", file, line, (unsigned int)pthread_self(), (node), (node)->references);
	REQUIRE(!is_marked(node));
	isc_refcount_increment(&node->references);
	return (node);
}

static void
_release_node(node_t **nodep, char *file, unsigned int line) {
	REQUIRE(nodep != NULL && *nodep != NULL);
	node_t *node = *nodep;
	fprintf(stderr, "%s:%u:%u: rlse_node: %p->%" PRIxFAST32 "\n", file, line, (unsigned int)pthread_self(), (node), (node)->references); \
	REQUIRE(!is_marked(node));
	if (isc_refcount_decrement(&(node)->references) == 1) {
		*nodep = NULL;
		node_free(node);
	}
}

static size_t
randomlevel(isc_pq_t *pq) {
	REQUIRE(pq->maxlevel <= 32);

	uint32_t r = isc_random32();
	size_t level = 1;

	r &= (1 << (pq->maxlevel - 1)) - 1;
	while ((r & 1)) {
		level++;
		r >>= 1;
	}

	INSIST(level < pq->maxlevel);
	return level;
}

static inline void
mark_next(node_t *node, size_t i) {
	uintptr_t tmp = atomic_load(&NODE_NEXT(node, i));
	while (!is_marked(tmp)) {
		if (atomic_compare_exchange_weak(&NODE_NEXT(node, i),
						 &tmp,
						 get_marked(tmp)))
		{
			break;
		}
	}
}

static inline bool
mark_value(isc_pq_t *pq, node_t **nextp, node_t *prev, uintptr_t *valuep) {
	/*
	 * Try to set this deletion mark using the CAS primitive, and if it
	 * succeeds it also writes a valid pointer to the prev field of the
	 * node.
	 *
	 * This prev field is necessary in order to increase the performance of
	 * concurrent HelpDelete operations, these operations otherwise would
	 * have to search for the previous node in order to complete the
	 * deletion.
	 */

	REQUIRE(nextp != NULL && *nextp != NULL);
	node_t *node = *nextp;
	uintptr_t value = atomic_load(&node->value);
	for (;;) {
		if (node != (node_t *)NODE_NEXT(prev, 0)) {
			release_node(&node);
			continue;
		}

		if (!is_marked(value)) {
			if (atomic_compare_exchange_weak(&node->value, &value,
							 get_marked(value)))
			{
				atomic_store(&NODE_PREV(prev), (uintptr_t)prev);
				*valuep = value;
				return (true);
			}
			continue;
		} else {
			/*
			 * The value is already marked, look for the
			 * next item on the list
			 */
			*nextp = node = HelpDelete(pq, node, 0);
			return (false);
		}
	}
}

static node_t *
_ReadNext(isc_pq_t *pq, node_t **prev, size_t level, char *file, unsigned int line) {
	if (is_marked(atomic_load(&(*prev)->value))) {
		*prev = HelpDelete(pq, *prev, level);
	}
	node_t *next = (node_t *)atomic_load(&NODE_NEXT(*prev, level));
	node_t *node = _read_node(&next, file, line);
	while (node == NULL) {
		*prev = HelpDelete(pq, *prev, level);
		next = (node_t *)atomic_load(&NODE_NEXT(*prev, level));
		node = _read_node(&next, file, line);
	}
	return (node);
}

/*
 * Returns next key, and puts prev key in *node1
 */
static node_t *
_ScanKey(isc_pq_t *pq, node_t **prev, size_t level, uint32_t key, char *file, unsigned int line) {
	fprintf(stderr, "%s:%u:%u: ScanKey  : %p, level = %zu, key = %u\n", file, line, (unsigned int)pthread_self(), *prev, level, key);
	REQUIRE(!is_marked(*prev));
	node_t *node = _ReadNext(pq, prev, level, file, line);
	while (node->key < key) {
		_release_node(prev, file, line);
		*prev = node;
		node = _ReadNext(pq, prev, level, file, line);
	}
	assert(node != PQ_HEAD(pq));
	return (node);
}

#define return_if_done(node, level)					\
	if (atomic_load(&NODE_NEXT(node, level)) == NODE_MARK) {	\
		break;							\
	}

#if defined(ISC_PQ_EXPONENTIAL_BACKOFF)
thread_local int swap_next_backoff = 0;
#endif

static inline void
swap_next(isc_pq_t *pq, node_t **prevp, node_t *node, size_t level, char *file, unsigned int line) {
#if defined(ISC_PQ_EXPONENTIAL_BACKOFF)
	swap_next_backoff = 2;
#endif
	for (;;) {
		node_t *prev = *prevp;
		node_t *last;
		fprintf(stderr, "%s:%u:%u: swap_next: node = %p, node->next[%zu] = %p, prev = %p, prev->next[%zu] = %p\n", file, line, (unsigned int)pthread_self(), node, level, (void *)(node->next[level]), prev, level, (void *)(prev->next[level]));

		/* pq.c:484:2578360064: swap_next: node = 0x7f889c001d20, node->next[1] = 0x1, prev = 0x7f889c001d20, prev->next[1] = 0x1 */

		return_if_done(node, level);

		last = ScanKey(pq, prevp, level, node->key);
		release_node(&last);

		if (last != node) {
			fprintf(stderr, "%s:%u:%u: swap_next: last = %p != node = %p\n", file, line, (unsigned int)pthread_self(), last, node);
			return;
		}
		return_if_done(node, level);
		if (atomic_compare_exchange_strong(
			    &NODE_NEXT(prev, level), (uintptr_t *)&node,
			    get_unmarked(
				    atomic_load(&NODE_NEXT(node, level)))))
		{
			atomic_store(&NODE_NEXT(node, level), NODE_MARK);
			return;
		}
		return_if_done(node, level);


#if defined(ISC_PQ_EXPONENTIAL_BACKOFF)
		usleep(swap_next_backoff);
		if (swap_next_backoff * 2 < 1000000) {
			swap_next_backoff *= 2;
		}
#else
		/* Back-Off */
		sched_yield();
#endif
	}
}
/* #undef return_if_done */

static inline void
insert_next(isc_pq_t *pq, node_t *newnode, size_t level, node_t *prev, uint32_t key) {
	atomic_store(&newnode->valid, level);
	for (;;) {
		node_t *oldnode = ScanKey(pq, &prev, level, key);
		atomic_store(&NODE_NEXT(newnode, level), (uintptr_t)oldnode);
		release_node(&oldnode);

		if (is_marked(newnode->value) ||
		    atomic_compare_exchange_strong(&NODE_NEXT(prev, level),
						   (uintptr_t *)&oldnode,
						   (uintptr_t)newnode))
		{
			release_node(&prev);
			break;
		}
		/* Back-Off */
		sched_yield();
	}
}

bool
Insert(isc_pq_t *pq, uint32_t key, void *value) {
	/* Requires aligned pointers */
	REQUIRE(!is_marked((uintptr_t)value));

	node_t *prev;
	node_t *newNode;
	node_t *savedNodes[pq->maxlevel];
	size_t level = randomlevel(pq);

	newNode = node_new(pq, level, key, value);
	copy_node(newNode);

	prev = COPY_HEAD(pq);

	for (size_t i = pq->maxlevel - 1; i > 0; i--) {
		GET_PREV(pq, &prev, i, key);
		if (i < level) {
			savedNodes[i] = copy_node(prev);
		}
	}
	for (;;) {
		node_t *node = ScanKey(pq, &prev, 0, key);
		uintptr_t value2 = atomic_load(&node->value);
		if (pq->unique && !is_marked(value2) && node->key == key) {
			if (atomic_compare_exchange_strong(&node->value, &value2,
							 (uintptr_t)value)) {
				release_node(&prev);
				release_node(&node);
				for (size_t i = 1; i < level; i++) {
					release_node(&savedNodes[i]);
				}
				release_node(&newNode);
				release_node(&newNode); /* Final Delete */
				return true;
			} else {
				release_node(&node);
				continue;
			}
		}
		atomic_init(&NODE_NEXT(newNode, 0), (uintptr_t)node);
		release_node(&node);
		if (atomic_compare_exchange_strong(&NODE_NEXT(prev, 0),
						 (uintptr_t *)&node,
						 (uintptr_t)newNode))
		{
			release_node(&prev);
			break;
		}
		/* Back-Off */
		sched_yield();
	}
	for (size_t i = 1; i < level; i++) {
		insert_next(pq, newNode, i, savedNodes[i], key);
	}
	atomic_store(&newNode->valid, level);
	/* Node has been already deleted before insert has finished */
	if (is_marked(newNode->value)) {
		newNode = HelpDelete(pq, newNode, 0);
	}
	release_node(&newNode);
	return true;
}

void
node_print(node_t *node, char *s, char *f, char *file, unsigned int line) {
	for (size_t i = 0; i < node->level; i++) {
		fprintf(stderr, "%s:%u:%u: %s: %s = %p, %s->next[%zu] = %p\n", file, line, (unsigned int)pthread_self(), f, s, node, s, i, (node_t *)node->next[i]);
	}
}

void *
DeleteMin(isc_pq_t *pq) {
	node_t *prev;
	node_t *node;
	void *value;

	node_print(PQ_HEAD(pq), "head", "DeleteStr", __FILE__, __LINE__);

	prev = COPY_HEAD(pq);
	/*
	 * Find the first node in the list that does not have is deletion mark
	 * on the value set.
	 */
	for (;;) {
		/* Find the next node */
		node = ReadNext(pq, &prev, 0);
		/* The next node is tail => the queue is empty */
		if (node == PQ_TAIL(pq)) {
			release_node(&prev);
			release_node(&node);
			return (NULL);
		}
		if (mark_value(pq, &node, prev, (uintptr_t *)&value)) {
			break;
		}
		release_node(&prev);
		prev = node;
	}
	node_print(prev, "prev", "DeleteStr", __FILE__, __LINE__);
	/*
	 * The next step is to mark the deletion bits of the next pointers in
	 * the node, starting with the lowest level and goint upwards, using
	 * the CAS primitive in each step.
	 */
	for (size_t i = 0; i < node->level; i++) {
		mark_next(node, i);
	}
	/*
	 * Afterwards it starts the actual deletion by changing the next
	 * pointers of the previous node, starting at the highest level and
	 * continuing downwards. The reason for doing the deletion in decreasing
	 * order of levels is that concurent search operations also start at the
	 * highest level and proceed downwards, in this way the cocurrent search
	 * operations will sooner avoid traversing this node. The procedure
	 * performed by the DeleteMin operation in order to change each next
	 * pointer of the previous node and then perform the CAS primitive until
	 * it succeeds.
	 */
	prev = COPY_HEAD(pq);
	for (int i = node->level-1; i >= 0; i--) {
		swap_next(pq, &prev, node, (size_t)i, __FILE__, __LINE__);
	}

	node_print(PQ_HEAD(pq), "head", "DeleteEnd", __FILE__, __LINE__);
	node_print(prev, "prev", "DeleteEnd", __FILE__, __LINE__);

	release_node(&prev);
	release_node(&node);
	release_node(&node); /* Delete Node */

	return (void *)value;
}

node_t *
HelpDelete(isc_pq_t *pq, node_t *node, size_t level) {
	/*
	 * The HelpDelete operation tries to fulfill the deeltion on the current
	 * level and returns when it is completed.
	 */
	REQUIRE(is_marked(node->value));
	node_t *prev;
	/*
	 * It starts with setting the deletion mark on all next pointers in
	 * case they have not been set.
	 */
	for (size_t i = level; i < node->level; i++) {
		mark_next(node, i);
	}
	/*
	 * It checks if the node given in the prev field is valid for deletion
	 * on the current level, otherwise it searches for the correct node.
	 */
	prev = (node_t *)atomic_load(&NODE_PREV(node));
	if (prev == NULL || level >= atomic_load(&prev->valid)) {
		prev = COPY_HEAD(pq);
		for (int i = pq->maxlevel - 1; i >= (int)level; i--) {
			GET_PREV(pq, &prev, i, node->key);
		}
	} else {
		copy_node(prev);
	}

	/*
	 * The actual deletion of this node on the current level. This operation
	 * might execute concurrently with the corresponding DeleteMin
	 * operation, and therefore both operations synchronize with each other
	 * in order to avoid executing sub-operations that have already been
	 * performed.
	 */
	swap_next(pq, &prev, node, level, __FILE__, __LINE__);

	release_node(&node);
	return prev;
}

uint64_t testdata[64] = { 0 };

static isc_refcount_t deletes = 0;
static isc_refcount_t inserts = 0;

static void *
insert_thread(void *arg) {
	isc_pq_t *pq = (isc_pq_t *)arg;

	for (size_t i = sizeof(testdata) / sizeof(testdata[0]); i > 0; i--) {
		/* fprintf(stderr, "Insert[%zu]: %p\n", i, &testdata[i - 1]); */
		Insert(pq, i, &testdata[i - 1]);
		(void)atomic_fetch_add(&inserts, 1);
	}
	return NULL;
}


static void *
delete_thread(void *arg) {
	isc_pq_t *pq = (isc_pq_t *)arg;

	for (size_t i = sizeof(testdata) / sizeof(testdata[0]); i > 0; i--) {
		(void)DeleteMin(pq);
		(void)atomic_fetch_add(&deletes, 1);
		/* fprintf(stderr, "Delete[%zu]: %p\n", i, ptr); */
	}
	return (NULL);
}

int
main(void) {
	isc_pq_t *pq = NULL;
	isc_mem_t *mctx = NULL;
	isc_mem_create(&mctx);

	pq = isc_mem_get(mctx, sizeof(*pq));
	*pq = (isc_pq_t) {
		.maxlevel = MAXLEVEL,
		.unique = false,
	};

	isc_mem_attach(mctx, &pq->mctx);

	node_t *head = node_new(pq, pq->maxlevel, 0, 0);
	node_t *tail = node_new(pq, 1, UINT32_MAX, 0);

	for (size_t i = 0; i < pq->maxlevel; i++) {
		atomic_init(&NODE_NEXT(head, i),
			    (uintptr_t)copy_node(tail));
	}
	atomic_init(&head->valid, MAXLEVEL);
	atomic_init(&tail->valid, 0);
	atomic_init(&NODE_PREV(tail), (uintptr_t)copy_node(head));
	atomic_init(&pq->head, (uintptr_t)copy_node(head));
	atomic_init(&pq->tail, (uintptr_t)copy_node(tail));

	fprintf(stderr, "Inserts = %" PRIuFAST32 ", Deletes = %" PRIuFAST32 "\n", atomic_load(&inserts), atomic_load(&deletes));

	(void)insert_thread(pq);

	size_t nthreads = 4;
	pthread_t threads[nthreads];
	for (size_t i = 0; i < nthreads; i++) {
		if ((i % 2) == 0) {
			pthread_create(&threads[i], NULL, insert_thread, pq);
		} else {
			pthread_create(&threads[i], NULL, delete_thread, pq);
		}
	}

	for (size_t i = 0; i < nthreads; i++) {
		pthread_join(threads[i], NULL);
	}

	fprintf(stderr, "Inserts = %" PRIuFAST32 ", Deletes = %" PRIuFAST32 "\n", atomic_load(&inserts), atomic_load(&deletes));

	(void)delete_thread(pq);

	fprintf(stderr, "Inserts = %" PRIuFAST32 ", Deletes = %" PRIuFAST32 "\n", atomic_load(&inserts), atomic_load(&deletes));

	while (head) {
		release_node(&head);
	}
	while (tail) {
		release_node(&tail);
	}

	isc_mem_putanddetach(&pq->mctx, pq, sizeof(*pq));

	isc_mem_detach(&mctx);

	isc_mem_checkdestroyed(stderr);

	return (0);
}
