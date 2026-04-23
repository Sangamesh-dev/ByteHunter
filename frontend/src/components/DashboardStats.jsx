export default function DashboardStats({ history }) {
  if (!Array.isArray(history) || history.length === 0) return null

  const total = history.length
  const malicious = history.filter(h => h.verdict === 'MALICIOUS').length
  const avgScore = total > 0 
    ? (history.reduce((acc, h) => acc + (Number(h.threat_score) || 0), 0) / total).toFixed(1) 
    : 0

  return (
    <div className="grid grid-cols-3 gap-4 mb-8">
      <div className="bg-surface border border-border p-4 rounded-lg">
        <div className="text-[10px] text-muted uppercase tracking-widest mb-1">Total Scanned</div>
        <div className="text-2xl font-bold">{total}</div>
      </div>
      <div className="bg-surface border border-border p-4 rounded-lg">
        <div className="text-[10px] text-muted uppercase tracking-widest mb-1">Malicious Detected</div>
        <div className="text-2xl font-bold text-red">{malicious}</div>
      </div>
      <div className="bg-surface border border-border p-4 rounded-lg">
        <div className="text-[10px] text-muted uppercase tracking-widest mb-1">Avg. Threat Score</div>
        <div className="text-2xl font-bold text-amber">{avgScore}%</div>
      </div>
    </div>
  )
}
