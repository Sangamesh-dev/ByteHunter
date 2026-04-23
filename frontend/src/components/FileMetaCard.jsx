export default function FileMetaCard({ result }) {
  if (!result) return null

  const rows = [
    { label: 'Filename', value: result.filename || 'N/A' },
    { label: 'File Type', value: result.file_type || 'N/A' },
    { label: 'File Size', value: result.file_size || '0 KB' },
    { label: 'SHA-256', value: result.sha256 || 'N/A', mono: true, truncate: true },
    { label: 'MD5', value: result.md5 || 'N/A', mono: true },
    { label: 'Model', value: result.model_used || 'N/A' },
    { label: 'Analysis Time', value: result.analysis_time_ms ? `${result.analysis_time_ms} ms` : 'N/A' },
    { label: 'Timestamp', value: result.timestamp ? new Date(result.timestamp).toLocaleString() : 'N/A' },
  ]

  return (
    <div className="bg-surface border border-border rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <div className="text-xs text-muted tracking-widest">FILE METADATA</div>
        <span className="text-xs bg-green/10 text-green border border-green/30 px-2 py-0.5 rounded-full">
          🔒 Isolated Environment
        </span>
      </div>
      <div className="space-y-2">
        {rows.map(({ label, value, mono, truncate }) => (
          <div key={label} className="flex gap-2 text-xs">
            <span className="text-muted w-28 shrink-0">{label}</span>
            <span
              className={`text-gray-300 break-all ${mono ? 'font-mono' : ''} ${
                truncate ? 'truncate max-w-[200px]' : ''
              }`}
              title={truncate ? value : undefined}
            >
              {value}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
