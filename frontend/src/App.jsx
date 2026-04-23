import { useState, useCallback, useEffect } from 'react'
import axios from 'axios'
import UploadZone from './components/UploadZone'
import ScanAnimation from './components/ScanAnimation'
import ThreatScoreGauge from './components/ThreatScoreGauge'
import VerdictBanner from './components/VerdictBanner'
import WarningSignsList from './components/WarningSignsList'
import ShapChart from './components/ShapChart'
import FileMetaCard from './components/FileMetaCard'
import ScanHistory from './components/ScanHistory'

// New Components
import ExplanationCard from './components/ExplanationCard'
import BehaviorSim from './components/BehaviorSim'
import DashboardStats from './components/DashboardStats'

const SCAN_STEPS = [
  'Uploading file...',
  'Computing file hash...',
  'Extracting PE headers...',
  'Analyzing import table...',
  'Computing section entropy...',
  'Running EMBER LightGBM inference...',
  'Generating SHAP explanation...',
  'Analysis complete.',
]

export default function App() {
  const [phase, setPhase] = useState('idle') // idle | scanning | results
  const [results, setResults] = useState([])
  const [error, setError] = useState(null)
  const [history, setHistory] = useState([])
  const [selectedResultIdx, setSelectedResultIdx] = useState(0)
  const [selectedHistory, setSelectedHistory] = useState(null)
  const [showComparison, setShowComparison] = useState(false)

  const displayed = selectedHistory || results[selectedResultIdx]

  const fetchHistory = useCallback(async () => {
    try {
      const res = await axios.get('/api/history')
      setHistory(res.data)
    } catch (err) {
      console.error('Failed to fetch history:', err)
    }
  }, [])

  useEffect(() => {
    fetchHistory()
  }, [fetchHistory])

  const handleFiles = useCallback(async (files) => {
    setError(null)
    setSelectedHistory(null)
    setPhase('scanning')
    setResults([])
    setSelectedResultIdx(0)

    const formData = new FormData()
    files.forEach(f => formData.append('files', f))

    try {
      const res = await axios.post('/api/analyze', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      setResults(res.data)
      setPhase('results')
      fetchHistory()
    } catch (err) {
      const msg = err.response?.data?.detail || 'Analysis failed. Please try again.'
      setError(msg)
      setPhase('idle')
    }
  }, [fetchHistory])

  const handleDownloadReport = async (scanId) => {
    if (!scanId) return
    window.location.href = `http://localhost:8000/api/report/${scanId}`
  }

  const handleHistoryClick = (item) => {
    setSelectedHistory(item)
    setPhase('results')
  }

  const handleReset = () => {
    setPhase('idle')
    setResults([])
    setSelectedResultIdx(0)
    setSelectedHistory(null)
    setError(null)
  }

  return (
    <div className="min-h-screen bg-bg text-white font-mono">
      {/* Header */}
      <header className="border-b border-border px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-green text-2xl">⬡</span>
          <span className="text-xl font-bold tracking-widest text-green">BYTEHUNTER</span>
          <span className="text-muted text-xs ml-2">AI Malware Scanner</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-muted">
          <span className="w-2 h-2 rounded-full bg-green inline-block animate-pulse" />
          SYSTEM ONLINE
        </div>
      </header>

      <div className="flex max-w-7xl mx-auto">
        {/* Sidebar — scan history */}
        <aside className="w-64 shrink-0 border-r border-border min-h-screen p-4 hidden lg:block">
          <ScanHistory history={history} onSelect={handleHistoryClick} />
        </aside>

        {/* Main content */}
        <main className="flex-1 p-6">
          {phase === 'idle' && (
            <div className="max-w-2xl mx-auto mt-12">
              <div className="text-center mb-8">
                <h1 className="text-3xl font-bold text-green mb-2">Scan a File</h1>
                <p className="text-muted text-sm">
                  Upload any file for instant AI-powered threat analysis.
                  <br />
                  Supports PE, PDF, Office, scripts, ZIPs — up to 50 MB.
                </p>
              </div>
              {error && (
                <div className="mb-4 p-3 border border-red rounded text-red text-sm">
                  ⚠ {error}
                </div>
              )}
              <UploadZone onFiles={handleFiles} disabled={phase === 'scanning'} />
              <div className="mt-8 pt-8 border-t border-border">
                <DashboardStats history={history} />
              </div>
            </div>
          )}

          {phase === 'scanning' && <ScanAnimation steps={SCAN_STEPS} />}

          {phase === 'results' && displayed && (
            <div className="max-w-4xl mx-auto">
              <button
                onClick={handleReset}
                className="mb-6 text-xs text-muted hover:text-green transition-colors flex items-center gap-1"
              >
                ← Back to Upload
              </button>

              <div className="flex items-center justify-between mb-4">
                <div className="flex gap-2">
                  {results.length > 1 && results.map((r, i) => (
                    <button
                      key={i}
                      onClick={() => { setSelectedHistory(null); setSelectedResultIdx(i); }}
                      className={`px-3 py-1 text-xs rounded border transition-all ${
                        !selectedHistory && selectedResultIdx === i 
                          ? 'bg-green text-bg border-green' 
                          : 'border-border text-muted hover:border-green/50'
                      }`}
                    >
                      FILE {i + 1}
                    </button>
                  ))}
                </div>
                <div className="flex items-center gap-4">
                  <button 
                    onClick={() => setShowComparison(!showComparison)}
                    className={`text-xs px-3 py-1 rounded border transition-colors ${showComparison ? 'bg-amber/10 border-amber/20 text-amber' : 'border-border text-muted'}`}
                  >
                    {showComparison ? 'Hide Comparison' : 'Compare Models'}
                  </button>
                  <button 
                    onClick={() => handleDownloadReport(displayed.scan_id)}
                    className="text-xs bg-green text-bg px-3 py-1 rounded font-bold hover:bg-green/90"
                  >
                    Download Report
                  </button>
                </div>
              </div>

              {displayed ? (
                <>
                  <VerdictBanner 
                    verdict={displayed.verdict} 
                    riskLevel={displayed.risk_level} 
                    cached={displayed.cached}
                  />

                  {displayed.warning_message && (
                    <div className="mt-4 p-3 bg-amber/10 border border-amber/20 rounded text-amber text-xs flex items-center gap-2">
                      <span>⚠</span> {displayed.warning_message}
                    </div>
                  )}

                  {displayed.model_disagreement_flag && (
                    <div className="text-xs text-amber mt-2 font-bold px-1">
                      ⚠️ Model disagreement detected. Confidence reduced.
                    </div>
                  )}
                </>
              ) : null}

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
                {/* Left column */}
                <div className="space-y-6">
                  <ThreatScoreGauge score={displayed.threat_score} />

                  {displayed.malware_type && (
                    <div className="bg-surface border border-border rounded-lg p-4">
                      <div className="text-xs text-muted mb-1">MALWARE CLASSIFICATION</div>
                      <div className="text-red font-bold text-lg">{displayed.malware_type}</div>
                      <p className="text-sm text-gray-400 mt-1 italic">{displayed.behavior_description}</p>
                    </div>
                  )}

                  <ExplanationCard 
                    explanations={displayed.explanations} 
                    summary={displayed.explanation_summary} 
                  />

                  {showComparison && displayed.model_comparison && (
                    <div className="bg-surface border border-border rounded-lg p-4 animate-in fade-in slide-in-from-top-2">
                      <div className="text-xs text-muted mb-3 flex items-center justify-between">
                        MODEL COMPARISON
                        <span className="text-green">{displayed.model_agreement}% AGREEMENT</span>
                      </div>
                      <div className="space-y-2">
                        {Object.entries(displayed.model_comparison).map(([name, score]) => (
                          <div key={name} className="flex items-center justify-between text-xs">
                            <span className="text-gray-400 capitalize">{name.replace('_', ' ')}</span>
                            <div className="flex items-center gap-2">
                              <div className="w-24 h-1 bg-bg rounded-full overflow-hidden">
                                <div className={`h-full ${score > 50 ? 'bg-red' : 'bg-green'}`} style={{ width: `${score}%` }} />
                              </div>
                              <span className="w-8 text-right font-mono">{score}%</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-surface border border-border rounded-lg p-3">
                      <div className="text-[10px] text-muted mb-1 uppercase tracking-widest">Confidence</div>
                      <div className={`text-sm font-bold ${displayed.confidence_level === 'HIGH' ? 'text-green' : displayed.confidence_level === 'MEDIUM' ? 'text-amber' : 'text-red'}`}>
                        {displayed.confidence_level} ({(displayed.confidence * 100).toFixed(0)}%)
                      </div>
                    </div>
                    <div className="bg-surface border border-border rounded-lg p-3">
                      <div className="text-[10px] text-muted mb-1 uppercase tracking-widest">Uncertainty</div>
                      <div className="text-sm font-bold">
                        ±{displayed.uncertainty.toFixed(1)}
                      </div>
                    </div>
                  </div>
                </div>

                {/* Right column */}
                <div className="space-y-6">
                  <BehaviorSim behaviors={displayed.simulated_behaviors} />
                  <FileMetaCard result={displayed} />
                  <WarningSignsList signs={displayed.warning_signs} />
                </div>
              </div>

              {/* SHAP chart — full width */}
              {displayed.shap_features?.length > 0 && (
                <div className="mt-6">
                  <ShapChart features={displayed.shap_features} />
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
