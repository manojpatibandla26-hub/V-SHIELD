/**
 * AI Sentinel API — mini-service entry (bun/node wrapper around uvicorn).
 *
 * `bun run dev` starts uvicorn with --reload, which watches *.py files and
 * auto-restarts the Python process on change (the bun --hot equivalent for
 * a Python service).
 */
const { spawn } = require('node:child_process')
const fs = require('node:fs')
const path = require('node:path')

const cwd = __dirname
const venvPython = path.join(cwd, '.venv', 'bin', 'python')
const venvPythonWin = path.join(cwd, '.venv', 'Scripts', 'python.exe')
const python = fs.existsSync(venvPython)
  ? venvPython
  : fs.existsSync(venvPythonWin)
    ? venvPythonWin
    : 'python3'

const PORT = process.env.AI_SENTINEL_PORT || '8000'

const args = [
  '-m', 'uvicorn', 'app.main:app',
  '--host', '0.0.0.0',
  '--port', PORT,
  '--reload',
  '--reload-include', '*.py',
]

console.log(`[ai-sentinel-api] starting: ${python} ${args.join(' ')}`)
const child = spawn(python, args, { cwd, stdio: 'inherit' })

const shutdown = (sig) => {
  console.log(`[ai-sentinel-api] ${sig} received — stopping uvicorn`)
  child.kill(sig)
  process.exit(0)
}
process.on('SIGINT', () => shutdown('SIGINT'))
process.on('SIGTERM', () => shutdown('SIGTERM'))
child.on('exit', (code) => {
  if (code !== 0 && code !== null) {
    console.error(`[ai-sentinel-api] uvicorn exited with code ${code}`)
  }
  process.exit(code ?? 0)
})
