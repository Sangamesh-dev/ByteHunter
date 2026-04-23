import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

export default function ScanAnimation({ steps }) {
  const [visibleCount, setVisibleCount] = useState(0)

  useEffect(() => {
    if (visibleCount >= steps.length) return
    const timer = setTimeout(() => setVisibleCount((c) => c + 1), 420)
    return () => clearTimeout(timer)
  }, [visibleCount, steps.length])

  return (
    <div className="max-w-xl mx-auto mt-20">
      <div className="bg-surface border border-border rounded-xl p-6 font-mono text-sm">
        <div className="flex items-center gap-2 mb-4 pb-3 border-b border-border">
          <span className="w-3 h-3 rounded-full bg-red/60" />
          <span className="w-3 h-3 rounded-full bg-amber/60" />
          <span className="w-3 h-3 rounded-full bg-green/60" />
          <span className="text-muted text-xs ml-2">bytehunter — analysis</span>
        </div>

        <AnimatePresence>
          {steps.slice(0, visibleCount).map((step, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2 }}
              className={`flex items-center gap-2 py-0.5 ${
                i === visibleCount - 1 ? 'text-green' : 'text-gray-500'
              }`}
            >
              <span className="text-muted">{'>'}</span>
              <span>{step}</span>
              {i === visibleCount - 1 && i < steps.length - 1 && (
                <span className="animate-pulse text-green">█</span>
              )}
            </motion.div>
          ))}
        </AnimatePresence>

        {visibleCount < steps.length && (
          <div className="mt-2 text-muted text-xs">
            <span className="animate-pulse">scanning...</span>
          </div>
        )}
      </div>
    </div>
  )
}
