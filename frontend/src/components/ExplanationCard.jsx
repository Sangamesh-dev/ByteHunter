import { motion } from 'framer-motion'

export default function ExplanationCard({ explanations, summary }) {
  if (!explanations || explanations.length === 0) return null

  return (
    <motion.div 
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className="bg-surface border border-border rounded-lg p-5"
    >
      <div className="flex items-center gap-2 mb-4">
        <span className="text-green text-sm font-bold">●</span>
        <h3 className="text-sm font-bold tracking-wider text-green">WHY THIS FILE IS DANGEROUS</h3>
      </div>
      
      <div className="space-y-4">
        {explanations.map((exp, i) => (
          <div key={i} className="border-l-2 border-border pl-4">
            <div className="text-xs text-muted uppercase tracking-tight mb-1">{exp.category}</div>
            <p className="text-sm text-gray-300">{exp.reason}</p>
          </div>
        ))}
      </div>

      <div className="mt-6 pt-4 border-t border-border">
        <p className="text-xs text-muted leading-relaxed italic">
          {summary}
        </p>
      </div>
    </motion.div>
  )
}
