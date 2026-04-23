import { motion } from 'framer-motion'

export default function WarningSignsList({ signs }) {
  if (!signs?.length) return null

  return (
    <div className="bg-surface border border-border rounded-xl p-4">
      <div className="text-xs text-muted mb-3 tracking-widest">WARNING SIGNS / IOCs</div>
      <ul className="space-y-2">
        {signs.map((sign, i) => (
          <motion.li
            key={i}
            initial={{ opacity: 0, x: -8 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: i * 0.07 }}
            className="flex items-start gap-2 text-sm text-gray-300"
          >
            <span className="text-red mt-0.5 shrink-0">▸</span>
            <span>{sign}</span>
          </motion.li>
        ))}
      </ul>
    </div>
  )
}
