/**
 * AI Sentinel API — mini-service entry (node/bun wrapper around uvicorn).
 *
 * Modes:
 *   node index.js               → dev mode: uvicorn --reload (auto-restart on *.py)
 *   node index.js --no-reload   → presentation mode: no reload, stable single process
 *   AI_SENTINEL_RELOAD=0        → same as --no-reload (env alternative)
 *
 * Guard: if the port is already in use, this wrapper exits immediately with
 * a clear message instead of spawning a duplicate/zombie uvicorn.
 */
const { spawn } = require('node:child_process')
const net = require('node:net')
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
const noReload =
  process.argv.includes('--no-reload') ||
  String(process.env.AI_SENTINEL_RELOAD || '').toLowerCase() === '0'

const args = [
  '-m', 'uvicorn', 'app.main:app',
  '--host', '0.0.0.0',
  '--port', PORT,
]
if (!noReload) {
  args.push('--reload', '--reload-dir', 'app', '--reload-exclude', '.venv', '--reload-exclude', 'pcaps')
}

function portInUse(port, host) {
  return new Promise((resolve) => {
    const sock = net.connect({ port: Number(port), host, timeout: 800 })
    sock.once('connect', () => { sock.destroy(); resolve(true) })
    sock.once('error', () => resolve(false))
    sock.once('timeout', () => { sock.destroy(); resolve(false) })
  })
}

async function main() {
  if (await portInUse(PORT, '127.0.0.1')) {
    console.error(
      `[ai-sentinel-api] ERROR: port ${PORT} is already in use — ` +
      `another backend instance is running. Only ONE instance should run.`
    )
    process.exit(1)
  }

  console.log(`[ai-sentinel-api] starting: ${python} ${args.join(' ')}`)
  const child = spawn(python, args, { cwd, stdio: 'inherit' })

  const shutdown = (sig) => {
    console.log(`[ai-sentinel-api] ${sig} received — stopping uvicorn`)
    child.kill(sig)
    setTimeout(() => process.exit(0), 1500)
  }
  process.on('SIGINT', () => shutdown('SIGINT'))
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  child.on('exit', (code) => {
    if (code !== 0 && code !== null) {
      console.error(`[ai-sentinel-api] uvicorn exited with code ${code}`)
    }
    process.exit(code ?? 0)
  })
}

main()
