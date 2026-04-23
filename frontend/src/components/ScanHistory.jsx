const VERDICT_COLORS = {
  SAFE: 'text-green border-green/30 bg-green/10',
  SUSPICIOUS: 'text-amber border-amber/30 bg-amber/10',
  MALICIOUS: 'text-red border-red/30 bg-red/10',
}

export default function ScanHistory({ history, onSelect }) {
  if (!Array.isArray(history)) return null

  return (
    <div>
      <div className="text-xs text-muted tracking-widest mb-3">SCAN HISTORY</div>
      {history.length === 0 ? (
        <p className="text-xs text-muted">No scans yet.</p>
      ) : (
        <ul className="space-y-2">
          {history.map((item, i) => (
            <li key={i}>
              <button
                onClick={() => onSelect(item)}
                className="w-full text-left p-2 rounded border border-border hover:border-green/40 transition-colors bg-surface hover:bg-green/5"
              >
                <div className="text-xs text-gray-300 truncate mb-1">{item.filename}</div>
                <div className="flex items-center justify-between">
                  <span
                    className={`text-xs px-1.5 py-0.5 rounded border ${VERDICT_COLORS[item.verdict]}`}
                  >
                    {item.verdict}
                  </span>
                  <span className="text-xs text-muted">{item.threat_score}</span>
                </div>
                <div className="text-xs text-muted mt-1">
                  {new Date(item.timestamp).toLocaleTimeString()}
                </div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}
