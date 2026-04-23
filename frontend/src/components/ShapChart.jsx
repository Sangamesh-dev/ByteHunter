import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'

const CustomTooltip = ({ active, payload }) => {
  if (!active || !payload?.length) return null
  const { feature, value } = payload[0].payload
  return (
    <div className="bg-surface border border-border rounded p-2 text-xs">
      <div className="text-gray-300">{feature}</div>
      <div className={value >= 0 ? 'text-red' : 'text-green'}>
        {value >= 0 ? '▲ Malicious' : '▼ Benign'}: {Math.abs(value).toFixed(4)}
      </div>
    </div>
  )
}

export default function ShapChart({ features }) {
  if (!Array.isArray(features) || features.length === 0) return null
  const sorted = [...features].sort((a, b) => Math.abs(b.value) - Math.abs(a.value))

  return (
    <div className="bg-surface border border-border rounded-xl p-4">
      <div className="text-xs text-muted mb-1 tracking-widest">SHAP FEATURE IMPORTANCE</div>
      <div className="text-xs text-muted mb-4">
        Red = pushes toward malicious &nbsp;|&nbsp; Green = pushes toward benign
      </div>
      <ResponsiveContainer width="100%" height={260}>
        <BarChart
          data={sorted}
          layout="vertical"
          margin={{ top: 0, right: 20, left: 160, bottom: 0 }}
        >
          <XAxis type="number" tick={{ fill: '#666', fontSize: 10 }} />
          <YAxis
            type="category"
            dataKey="feature"
            tick={{ fill: '#aaa', fontSize: 11, fontFamily: 'JetBrains Mono' }}
            width={155}
          />
          <Tooltip content={<CustomTooltip />} />
          <Bar dataKey="value" radius={[0, 3, 3, 0]}>
            {sorted.map((entry, i) => (
              <Cell key={i} fill={entry.value >= 0 ? '#ff4444' : '#00ff88'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
