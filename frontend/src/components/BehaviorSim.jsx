import { motion } from 'framer-motion'

const SEVERITY_COLORS = {
  HIGH: 'text-red bg-red/10 border-red/20',
  MEDIUM: 'text-amber bg-amber/10 border-amber/20',
  LOW: 'text-green bg-green/10 border-green/20'
}

export default function BehaviorSim({ behaviors }) {
  if (!behaviors || behaviors.length === 0) return null

  return (
    <div className="bg-surface border border-border rounded-lg p-5">
      <div className="text-xs text-muted mb-4 tracking-widest uppercase">Possible Behaviors</div>
      <div className="space-y-3">
        {behaviors.map((b, i) => (
          <motion.div 
            initial={{ x: -10, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            transition={{ delay: i * 0.1 }}
            key={i} 
            className="flex items-center justify-between p-3 bg-bg/50 border border-border rounded"
          >
            <div className="flex items-center gap-3">
              <span className="text-lg">
                {b.name === 'Network Download' ? '🌐' : 
                 b.name === 'Code Injection' ? '💉' : 
                 b.name === 'Persistence' ? '📌' : '⚙️'}
              </span>
              <span className="text-sm font-medium tracking-wide">{b.name}</span>
            </div>
            <span className={`text-[10px] px-2 py-0.5 rounded border ${SEVERITY_COLORS[b.severity] || SEVERITY_COLORS.LOW}`}>
              {b.severity}
            </span>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
