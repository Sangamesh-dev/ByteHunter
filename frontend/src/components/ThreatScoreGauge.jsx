import { motion } from 'framer-motion'

function scoreColor(score) {
  if (score < 30) return '#00ff88'
  if (score <= 65) return '#ffaa00'
  return '#ff4444'
}

export default function ThreatScoreGauge({ score }) {
  score = Math.max(0, Math.min(100, Number(score) || 0))
  const color = scoreColor(score)
  const radius = 70
  const circumference = 2 * Math.PI * radius
  // Arc covers 270 degrees (from 135° to 405°)
  const arcLength = circumference * 0.75
  const filled = arcLength * (score / 100)

  return (
    <div className="bg-surface border border-border rounded-xl p-6 flex flex-col items-center">
      <div className="text-xs text-muted mb-3 tracking-widest">THREAT SCORE</div>
      <div className="relative">
        <svg width="180" height="180" viewBox="0 0 180 180">
          {/* Background arc */}
          <circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke="#1e1e1e"
            strokeWidth="12"
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeDashoffset={0}
            strokeLinecap="round"
            transform="rotate(135 90 90)"
          />
          {/* Filled arc */}
          <motion.circle
            cx="90" cy="90" r={radius}
            fill="none"
            stroke={color}
            strokeWidth="12"
            strokeDasharray={`${arcLength} ${circumference}`}
            strokeLinecap="round"
            transform="rotate(135 90 90)"
            initial={{ strokeDashoffset: arcLength }}
            animate={{ strokeDashoffset: arcLength - filled }}
            transition={{ duration: 1, ease: 'easeOut' }}
          />
        </svg>
        <motion.div
          className="absolute inset-0 flex flex-col items-center justify-center"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          <span className="text-4xl font-bold" style={{ color }}>{score}</span>
          <span className="text-xs text-muted">/ 100</span>
        </motion.div>
      </div>
    </div>
  )
}
