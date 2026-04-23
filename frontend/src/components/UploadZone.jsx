import { useCallback } from 'react'
import { useDropzone } from 'react-dropzone'
import { motion } from 'framer-motion'

const MAX_SIZE = 50 * 1024 * 1024

export default function UploadZone({ onFiles, disabled }) {
  const onDrop = useCallback(
    (accepted) => {
      if (accepted.length > 5) {
        alert("Max 5 files allowed")
        onFiles(accepted.slice(0, 5))
      } else if (accepted.length > 0) {
        onFiles(accepted)
      }
    },
    [onFiles]
  )

  const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
    onDrop,
    maxSize: MAX_SIZE,
    multiple: true,
    disabled: disabled
  })

  const rejected = fileRejections[0]?.errors[0]?.message

  return (
    <div>
      <motion.div
        {...getRootProps()}
        whileHover={{ scale: 1.01 }}
        className={`
          border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-colors
          ${isDragActive
            ? 'border-green bg-green/5 text-green'
            : 'border-border hover:border-green/50 text-muted hover:text-gray-300'
          }
        `}
      >
        <input {...getInputProps()} />
        <div className="text-5xl mb-4">{isDragActive ? '📂' : '📁'}</div>
        <p className="text-lg font-semibold mb-1">
          {isDragActive ? 'Drop to scan...' : 'Drag & drop a file here'}
        </p>
        <p className="text-sm">or click to browse — max 50 MB</p>
        <p className="text-xs mt-3 text-muted">
          Supports: .exe .dll .pdf .docx .zip .js .py and more
        </p>
      </motion.div>
      {rejected && (
        <p className="text-red text-xs mt-2 text-center">⚠ {rejected}</p>
      )}
    </div>
  )
}
