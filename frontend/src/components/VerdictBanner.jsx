import { motion } from 'framer-motion'

const VERDICT_CONFIG = {
  SAFE: {
    label: 'SAFE TO OPEN',
    icon: '🛡',
    bg: 'bg-green/10',
    border: 'border-green',
    text: 'text-green',
  },
  SUSPICIOUS: {
    label: 'SUSPICIOUS',
    icon: '⚠',
    bg: 'bg-amber/10',
    border: 'border-amber',
    text: 'text-amber',
  },
  MALICIOUS: {
    label: 'DO NOT OPEN',
    icon: '☠',
    bg: 'bg-red/10',
    border: 'border-red',
    text: 'text-red',
  },
}

const RISK_COLORS = {
  LOW: 'bg-green/20 text-green border-green/40',
  MEDIUM: 'bg-amber/20 text-amber border-amber/40',
  HIGH: 'bg-red/20 text-red border-red/40',
}

export default function VerdictBanner({ verdict, riskLevel, cached }) {
  const isSafe = verdict === 'SAFE'
  const isMalicious = verdict === 'MALICIOUS'
  const isSuspicious = verdict === 'SUSPICIOUS'

  const borderClass = isMalicious ? 'border-red/50' : isSuspicious ? 'border-amber/50' : 'border-green/50'
  const bgClass = isMalicious ? 'bg-red/5' : isSuspicious ? 'bg-amber/5' : 'bg-green/5'
  const textClass = isMalicious ? 'text-red' : isSuspicious ? 'text-amber' : 'text-green'

  return (
    <div className={`p-6 rounded-xl border-2 ${borderClass} ${bgClass}`}>
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className={`text-3xl font-black tracking-tighter ${textClass}`}>
              {verdict}
            </div>
            {cached && (
              <span className="bg-border text-muted text-[10px] px-2 py-1 rounded font-bold uppercase tracking-widest">
                Cached Result
              </span>
            )}
          </div>
          <div className="text-sm mt-1 text-gray-400">
            {isMalicious ? 'Threat analysis indicates a high risk of malicious content.' : 
             isSuspicious ? 'Analysis flagged suspicious indicators. File integrity uncertain.' : 
             'No known malicious markers found by AI pipeline.'}
          </div>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-muted uppercase tracking-widest">Risk Level</div>
          <div className={`text-xl font-bold ${textClass}`}>{riskLevel}</div>
        </div>
      </div>
    </div>
  )
}
