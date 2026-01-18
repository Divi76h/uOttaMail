import React, { useEffect, useMemo, useState } from 'react'

function api(path, opts = {}) {
  return fetch(`/api${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      ...(opts.headers || {})
    }
  })
}

function authedApi(token, path, opts = {}) {
  return api(path, {
    ...opts,
    headers: {
      ...(opts.headers || {}),
      Authorization: `Bearer ${token}`
    }
  })
}

export default function App() {
  const [mode, setMode] = useState('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [token, setToken] = useState(localStorage.getItem('jwt') || '')

  const [emails, setEmails] = useState([])
  const [selectedId, setSelectedId] = useState(null)

  const [toUser, setToUser] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')

  // Derive selected email from ID
  const selected = useMemo(() => 
    selectedId ? emails.find(e => e.id === selectedId) : null,
    [selectedId, emails]
  )

  const authed = useMemo(() => ({
    token,
    refreshEmails: async () => {
      const res = await authedApi(token, '/emails/')
      if (res.ok) {
        setEmails(await res.json())
      }
    }
  }), [token])

  useEffect(() => {
    if (!token) return
    authed.refreshEmails()

    const es = new EventSource(`/api/events/stream/?token=${encodeURIComponent(token)}`)
    es.addEventListener('connected', () => {
      // no-op
    })
    es.onmessage = () => {
      authed.refreshEmails()
    }
    es.addEventListener('email.spam_classified', () => authed.refreshEmails())
    es.addEventListener('email.priority_assigned', () => authed.refreshEmails())
    es.addEventListener('email.summary', () => authed.refreshEmails())
    es.addEventListener('email.action_items', () => authed.refreshEmails())
    es.addEventListener('email.tone_analyzed', () => authed.refreshEmails())
    es.addEventListener('email.url_scanned', () => authed.refreshEmails())

    return () => es.close()
  }, [token])

  async function doAuth() {
    if (mode === 'register') {
      const r = await api('/auth/register/', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      })
      if (!r.ok) {
        alert('Register failed')
        return
      }
    }

    const res = await api('/auth/token/', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    })
    if (!res.ok) {
      alert('Login failed')
      return
    }
    const data = await res.json()
    localStorage.setItem('jwt', data.access)
    setToken(data.access)
  }

  async function sendEmail() {
    const res = await authedApi(token, '/emails/', {
      method: 'POST',
      body: JSON.stringify({ recipient_username: toUser, subject, body })
    })
    if (!res.ok) {
      alert('Send failed')
      return
    }
    setToUser('')
    setSubject('')
    setBody('')
    alert('Sent')
  }

  if (!token) {
    return (
      <div style={{ maxWidth: 520, margin: '40px auto', fontFamily: 'system-ui' }}>
        <h1>AI Inbox Firewall</h1>
        <p>Internal demo email system with Solace Agent Mesh agents.</p>

        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <button onClick={() => setMode('login')} disabled={mode === 'login'}>Login</button>
          <button onClick={() => setMode('register')} disabled={mode === 'register'}>Register</button>
        </div>

        <input
          placeholder="username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          style={{ width: '100%', padding: 8, marginBottom: 8 }}
        />
        <input
          placeholder="password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          style={{ width: '100%', padding: 8, marginBottom: 16 }}
        />
        <button onClick={doAuth} style={{ padding: 10, width: '100%' }}>
          {mode === 'register' ? 'Register + Login' : 'Login'}
        </button>
      </div>
    )
  }

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '340px 1fr', height: '100vh', fontFamily: 'system-ui' }}>
      <div style={{ borderRight: '1px solid #eee', padding: 12, overflowY: 'auto' }}>
        <h2 style={{ marginTop: 0 }}>Inbox</h2>
        <button
          onClick={() => {
            localStorage.removeItem('jwt')
            setToken('')
          }}
        >
          Logout
        </button>

        <h3>Compose</h3>
        <input placeholder="to username" value={toUser} onChange={(e) => setToUser(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
        <input placeholder="subject" value={subject} onChange={(e) => setSubject(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8 }} />
        <textarea placeholder="body" value={body} onChange={(e) => setBody(e.target.value)} style={{ width: '100%', padding: 8, marginBottom: 8, minHeight: 80 }} />
        <button onClick={sendEmail} style={{ width: '100%', padding: 10 }}>Send</button>

        <hr />

        {emails.map((e) => (
          <div
            key={e.id}
            onClick={() => setSelectedId(e.id)}
            style={{
              padding: 10,
              marginBottom: 8,
              border: '1px solid #eee',
              cursor: 'pointer',
              background: selected?.id === e.id ? '#f5f5f5' : 'white'
            }}
          >
            <div style={{ fontWeight: 600 }}>{e.subject}</div>
            <div style={{ fontSize: 12, opacity: 0.8 }}>From: {e.sender_username || 'unknown'}</div>
            <div style={{ fontSize: 12, marginTop: 6 }}>
              <span>Spam: {e.spam_label || '...'}</span>
              {'  |  '}
              <span>Priority: {e.priority || '...'}</span>
            </div>
          </div>
        ))}
      </div>

      <div style={{ padding: 16, overflowY: 'auto' }}>
        {!selected ? (
          <p>Select an email.</p>
        ) : (
          <div>
            <h2 style={{ marginTop: 0 }}>{selected.subject}</h2>
            <p style={{ marginTop: 0, opacity: 0.8 }}>From: {selected.sender_username || 'unknown'}</p>

            <h3>Body</h3>
            <pre style={{ whiteSpace: 'pre-wrap' }}>{selected.body}</pre>

            <h3>Agent Outputs</h3>
            <p><b>Spam</b>: {selected.spam_label || '...'} {selected.spam_reason ? `(${selected.spam_reason})` : ''}</p>
            <p><b>Priority</b>: {selected.priority || '...'} {selected.priority_reason ? `(${selected.priority_reason})` : ''}</p>
            <p><b>Summary</b>:</p>
            <pre style={{ whiteSpace: 'pre-wrap' }}>{selected.summary || '...'}</pre>
            <p><b>Action items</b>:</p>
            <pre style={{ whiteSpace: 'pre-wrap' }}>{selected.action_items ? JSON.stringify(selected.action_items, null, 2) : '...'}</pre>
            <p><b>Tone</b>: {selected.tone_emotion || '...'} {selected.tone_confidence ? `(${selected.tone_confidence})` : ''}</p>
            {selected.tone_explanation && <p style={{ fontStyle: 'italic', opacity: 0.8 }}>{selected.tone_explanation}</p>}
            
            <p><b>URL Security</b>: {selected.url_scan_verdict || '...'} {selected.url_scan_threat_level ? `(${selected.url_scan_threat_level})` : ''}</p>
            {selected.url_scan_summary && <p style={{ opacity: 0.8 }}>{selected.url_scan_summary}</p>}
            {selected.url_scan_details && <p style={{ fontStyle: 'italic', opacity: 0.8 }}>{selected.url_scan_details}</p>}
            {(selected.url_scan_malicious_count > 0 || selected.url_scan_suspicious_count > 0) && (
              <p style={{ color: selected.url_scan_malicious_count > 0 ? '#d32f2f' : '#ff9800', fontWeight: 600 }}>
                ⚠️ {selected.url_scan_malicious_count || 0} malicious, {selected.url_scan_suspicious_count || 0} suspicious
              </p>
            )}

            <button onClick={authed.refreshEmails}>Refresh</button>
          </div>
        )}
      </div>
    </div>
  )
}
