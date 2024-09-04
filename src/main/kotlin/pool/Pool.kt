package perun_network.ecdsa_threshold.pool

import java.io.Reader
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

// searchAlone runs f, which may return null, until count elements are found
fun searchAlone(f: () -> Any?, count: Int): List<Any?> {
    val results = MutableList<Any?>(count) { null }
    for (i in results.indices) {
        results[i] = null
        while (results[i] == null) {
            results[i] = f()
        }
    }
    return results
}

// parallelizeAlone calculates the result of f count times
fun parallelizeAlone(f: (Int) -> Any?, count: Int): List<Any?> {
    return List(count) { i -> f(i) }
}

// workerSearch is the subroutine called when doing a search command.
fun workerSearch(results: MutableList<Any?>, ctrChanged: () -> Unit, f: (Int) -> Any?, ctr: AtomicLong) {
    while (ctr.get() > 0) {
        val res = f(0) ?: continue
        val i = ctr.decrementAndGet()
        if (i >= 0) {
            results[i.toInt()] = res
        }
        ctrChanged()
    }
}

// worker starts up a new worker, listening to commands, and producing results
fun worker(commands: List<Command>) {
    for (c in commands) {
        if (c.search) {
            workerSearch(c.results, c.ctrChanged, c.f, c.ctr)
        } else {
            c.results[c.i] = c.f(c.i)
            c.ctr.decrementAndGet()
            c.ctrChanged()
        }
    }
}

// Command is used to trigger our latent workers to do something.
data class Command(
    val search: Boolean,
    val ctr: AtomicLong,
    val ctrChanged: () -> Unit,
    val i: Int = 0,
    val f: (Int) -> Any?,
    val results: MutableList<Any?>
)

class Pool private constructor(
    val commands: MutableList<Command> = mutableListOf(),
    val workerCount: Int
) {

    // NewPool creates a new Pool, with a certain number of workers
    companion object {
        fun newPool(count: Int): Pool {
            val pool = Pool(workerCount = if (count < 0) Runtime.getRuntime().availableProcessors() else count)
            for (i in 0 until pool.workerCount) {
                thread { worker(pool.commands) }
            }
            return pool
        }
    }

    // TearDown cleanly tears down a pool, closing channels, etc.
    fun tearDown() {
        commands.clear()
    }

    // Search queries the function f, until count successes are found.
    fun search(count: Int, f: () -> Any?): List<Any?> {
        if (commands.isEmpty()) return searchAlone(f, count)

        val results = MutableList<Any?>(count) { null }
        val ctr = AtomicLong(count.toLong())
        val ctrChanged = { /* signal change if needed */ }

        val cmd = Command(
            search = true,
            ctr = ctr,
            ctrChanged = ctrChanged,
            f = { f() },
            results = results
        )

        var cmdI = 0
        while (cmdI < workerCount) {
            if (commands.size < workerCount) {
                commands.add(cmd)
                cmdI++
            } else {
                ctrChanged()
            }
        }
        while (ctr.get() > 0) {
            ctrChanged()
        }

        return results
    }

    // Parallelize calls a function count times, passing in indices from 0..count-1.
    fun parallelize(count: Int, f: (Int) -> Any?): List<Any?> {
        if (commands.isEmpty()) return parallelizeAlone(f, count)

        val results = MutableList<Any?>(count) { null }
        val ctr = AtomicLong(count.toLong())
        val ctrChanged = { /* signal change if needed */ }
        var cmdI = 0

        while (cmdI < count) {
            val cmd = Command(
                search = false,
                i = cmdI,
                ctr = ctr,
                ctrChanged = ctrChanged,
                f = f,
                results = results
            )
            if (commands.size < workerCount) {
                commands.add(cmd)
                cmdI++
            } else {
                ctrChanged()
            }
        }
        while (ctr.get() > 0) {
            ctrChanged()
        }

        return results
    }

    // LockedReader wraps a Reader to be safe for concurrent reads.
    class LockedReader(private val reader: Reader) : Reader() {
        private val lock = Any()

        override fun read(cbuf: CharArray, off: Int, len: Int): Int {
            synchronized(lock) {
                return reader.read(cbuf, off, len)
            }
        }

        override fun close() {
            synchronized(lock) {
                reader.close()
            }
        }
    }
}
