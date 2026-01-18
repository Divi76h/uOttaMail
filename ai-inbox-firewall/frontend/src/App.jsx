import React, { useEffect, useMemo, useState, useCallback, useRef } from 'react'

// Toast notification component
function Toast({ toasts, removeToast }) {
  return (
    <div className="toast-container">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`toast toast-${toast.type}`}
          onClick={() => removeToast(toast.id)}
        >
          <div className="toast-icon">
            {toast.type === 'success' && '✓'}
            {toast.type === 'error' && '✕'}
            {toast.type === 'info' && 'ℹ'}
            {toast.type === 'warning' && '⚠'}
          </div>
          <div className="toast-content">
            <div className="toast-title">{toast.title}</div>
            {toast.message && <div className="toast-message">{toast.message}</div>}
          </div>
        </div>
      ))}
    </div>
  )
}

// Debounce hook
function useDebounce(value, delay) {
  const [debouncedValue, setDebouncedValue] = useState(value)
  
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedValue(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])
  
  return debouncedValue
}

// Format AI response with markdown-like formatting
function formatAiResponse(text, emails = []) {
  if (!text) return '';
  
  let formatted = text
    // Escape HTML first
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
  
  // Convert email IDs to clickable links
  // Only match explicit patterns like "Email ID: 5", "email #5", "ID 5", "id: 5"
  // Don't match bare numbers that could be times, dates, etc.
  formatted = formatted.replace(/\b(?:email\s+)?(?:id|ID)[:\s]+#?(\d+)\b/gi, (match, id) => {
    const emailId = parseInt(id);
    const email = emails.find(e => e.id === emailId);
    if (email) {
      return `<span class="ai-email-id-link" data-email-id="${emailId}" title="Click to view: ${email.subject.replace(/"/g, '&quot;')}">\ud83d\udce7 ${email.subject.substring(0, 30)}${email.subject.length > 30 ? '...' : ''}</span>`;
    }
    return match;
  });
  
  formatted = formatted
    // Bold: **text** or __text__
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    .replace(/__(.+?)__/g, '<strong>$1</strong>')
    // Italic: *text* or _text_
    .replace(/\*([^*]+)\*/g, '<em>$1</em>')
    .replace(/_([^_]+)_/g, '<em>$1</em>')
    // Code: `code`
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    // Numbered lists: 1. item
    .replace(/^(\d+)\.\s+(.+)$/gm, '<li class="numbered">$2</li>')
    // Bullet points: - item or * item
    .replace(/^[-*•]\s+(.+)$/gm, '<li>$1</li>')
    // Headers: ### header
    .replace(/^###\s+(.+)$/gm, '<h4>$1</h4>')
    .replace(/^##\s+(.+)$/gm, '<h3>$1</h3>')
    .replace(/^#\s+(.+)$/gm, '<h3>$1</h3>')
    // Line breaks
    .replace(/\n\n/g, '</p><p>')
    .replace(/\n/g, '<br/>');
  
  // Wrap lists in ul tags
  formatted = formatted.replace(/(<li.*?<\/li>)+/g, '<ul>$&</ul>');
  
  // Wrap in paragraph if not already wrapped
  if (!formatted.startsWith('<')) {
    formatted = '<p>' + formatted + '</p>';
  }
  
  return formatted;
}

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
  const [activeView, setActiveView] = useState('inbox')
  const [allActionItems, setAllActionItems] = useState([])

  const [toUser, setToUser] = useState('')
  const [subject, setSubject] = useState('')
  const [body, setBody] = useState('')

  // Search state
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState([])
  const [isSearching, setIsSearching] = useState(false)
  const [aiEnabled, setAiEnabled] = useState(true)
  const [aiResponse, setAiResponse] = useState(null)
  const [isAiLoading, setIsAiLoading] = useState(false)
  
  // UI state for panels
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [emailPaneWidth, setEmailPaneWidth] = useState(500)
  const [isResizing, setIsResizing] = useState(false)
  const [showEmailDetail, setShowEmailDetail] = useState(true)
  
  const debouncedSearch = useDebounce(searchQuery, 300)

  // Toast notifications
  const [toasts, setToasts] = useState([])
  
  const showToast = useCallback((type, title, message = '') => {
    const id = Date.now()
    setToasts(prev => [...prev, { id, type, title, message }])
    setTimeout(() => {
      setToasts(prev => prev.filter(t => t.id !== id))
    }, 4000)
  }, [])

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

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
    },
    refreshActionItems: async () => {
      const res = await authedApi(token, '/action-items/')
      if (res.ok) {
        setAllActionItems(await res.json())
      }
    },
    searchEmails: async (query) => {
      if (!query.trim()) {
        setSearchResults([])
        return []
      }
      setIsSearching(true)
      try {
        const res = await authedApi(token, `/search/?q=${encodeURIComponent(query)}`)
        if (res.ok) {
          const results = await res.json()
          setSearchResults(results)
          return results
        }
      } finally {
        setIsSearching(false)
      }
      return []
    },
    sendChatQuery: async (query) => {
      if (!query.trim()) return null
      setIsAiLoading(true)
      setAiResponse(null)
      try {
        const res = await authedApi(token, '/chat/', {
          method: 'POST',
          body: JSON.stringify({ query })
        })
        if (res.ok) {
          const data = await res.json()
          // Response will come via SSE, keep loading state
          return data
        } else {
          setIsAiLoading(false)
          setAiResponse({ response: 'Failed to send query', error: true })
        }
      } catch (e) {
        console.error('Chat query failed:', e)
        setIsAiLoading(false)
        setAiResponse({ response: 'Failed to send query', error: true })
      }
      return null
    },
    toggleActionItem: async (emailId, index) => {
      const res = await authedApi(token, `/action-items/${emailId}/${index}/toggle/`, {
        method: 'PATCH'
      })
      if (res.ok) {
        // Refresh both emails and action items to update UI
        const emailsRes = await authedApi(token, '/emails/')
        if (emailsRes.ok) setEmails(await emailsRes.json())
        const itemsRes = await authedApi(token, '/action-items/')
        if (itemsRes.ok) setAllActionItems(await itemsRes.json())
      }
    }
  }), [token])

  // Debounced text search effect (live as you type)
  useEffect(() => {
    if (!token || !debouncedSearch) {
      setSearchResults([])
      return
    }
    
    // Text search only (fast, live updates)
    authed.searchEmails(debouncedSearch)
  }, [debouncedSearch, token])

  // Resizable pane handlers
  const handleMouseDown = useCallback((e) => {
    e.preventDefault()
    setIsResizing(true)
  }, [])

  useEffect(() => {
    let rafId = null
    const sidebarWidth = sidebarCollapsed ? 70 : 240
    
    const handleMouseMove = (e) => {
      if (!isResizing) return
      if (rafId) cancelAnimationFrame(rafId)
      rafId = requestAnimationFrame(() => {
        const newWidth = e.clientX - sidebarWidth
        if (newWidth >= 250 && newWidth <= 800) {
          setEmailPaneWidth(newWidth)
        }
      })
    }
    
    const handleMouseUp = () => {
      setIsResizing(false)
      if (rafId) cancelAnimationFrame(rafId)
    }
    
    if (isResizing) {
      document.addEventListener('mousemove', handleMouseMove)
      document.addEventListener('mouseup', handleMouseUp)
      document.body.style.cursor = 'col-resize'
      document.body.style.userSelect = 'none'
    }
    
    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
      if (rafId) cancelAnimationFrame(rafId)
    }
  }, [isResizing, sidebarCollapsed])

  // Handle Enter key for AI search
  const handleSearchKeyDown = useCallback((e) => {
    if (e.key === 'Enter' && searchQuery.trim() && aiEnabled) {
      e.preventDefault()
      // Clear text search results when using AI
      setSearchResults([])
      authed.sendChatQuery(searchQuery.trim())
    }
  }, [searchQuery, aiEnabled, authed])

  useEffect(() => {
    if (!token) return
    authed.refreshEmails()
    authed.refreshActionItems()

    const es = new EventSource(`/api/events/stream/?token=${encodeURIComponent(token)}`)
    es.addEventListener('connected', () => {
      // no-op
    })
    es.onmessage = (ev) => {
      try {
        const data = JSON.parse(ev.data)
        if (data.event_type === 'email.new') {
          showToast('info', 'New Email', `From: ${data.sender_username || 'unknown'} — ${data.subject || 'No subject'}`)
        }
      } catch (e) {}
      authed.refreshEmails()
    }
    es.addEventListener('email.spam_classified', () => authed.refreshEmails())
    es.addEventListener('email.priority_assigned', () => authed.refreshEmails())
    es.addEventListener('email.summary', () => authed.refreshEmails())
    es.addEventListener('email.action_items', () => { authed.refreshEmails(); authed.refreshActionItems(); })
    es.addEventListener('email.tone_analyzed', () => authed.refreshEmails())
    es.addEventListener('email.url_scanned', () => authed.refreshEmails())
    
    // Handle AI chat responses
    es.addEventListener('email.chat_response', (ev) => {
      try {
        const data = JSON.parse(ev.data)
        console.log('[SSE] Chat response received:', data)
        setIsAiLoading(false)
        setAiResponse({ response: data.response, request_id: data.request_id })
      } catch (e) {
        console.error('Failed to parse chat response:', e)
        setIsAiLoading(false)
      }
    })

    return () => es.close()
  }, [token, showToast])

  async function doAuth() {
    if (mode === 'register') {
      const r = await api('/auth/register/', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      })
      if (!r.ok) {
        const err = await r.json().catch(() => ({}))
        showToast('error', 'Registration Failed', err.detail || err.username?.[0] || 'Could not create account. Username may already exist.')
        return
      }
      showToast('success', 'Account Created', 'Welcome! Logging you in...')
    }

    const res = await api('/auth/token/', {
      method: 'POST',
      body: JSON.stringify({ username, password })
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      showToast('error', 'Login Failed', err.detail || 'Invalid username or password.')
      return
    }
    const data = await res.json()
    localStorage.setItem('jwt', data.access)
    setToken(data.access)
    showToast('success', 'Welcome Back', `Logged in as ${username}`)
  }

  async function sendEmail() {
    if (!toUser.trim()) {
      showToast('warning', 'Missing Recipient', 'Please enter a username to send to.')
      return
    }
    if (!subject.trim()) {
      showToast('warning', 'Missing Subject', 'Please enter a subject for your email.')
      return
    }
    const res = await authedApi(token, '/emails/', {
      method: 'POST',
      body: JSON.stringify({ recipient_username: toUser, subject, body })
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      showToast('error', 'Send Failed', err.detail || `Could not send email to "${toUser}". User may not exist.`)
      return
    }
    const recipient = toUser
    setToUser('')
    setSubject('')
    setBody('')
    showToast('success', 'Email Sent', `Your message was delivered to ${recipient}`)
  }

  const [isComposeOpen, setIsComposeOpen] = useState(false)

  if (!token) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <div className="sidebar-logo" style={{ margin: '0 auto 1.5rem auto' }}>✉</div>
          <h1 className="auth-title">uOttaMail</h1>
          <p className="auth-subtitle">AI-powered inbox firewall by Solace Agent Mesh</p>

          <div className="auth-tabs">
            <button
              className={mode === 'login' ? 'active' : ''}
              onClick={() => setMode('login')}
            >
              Log In
            </button>
            <button
              className={mode === 'register' ? 'active' : ''}
              onClick={() => setMode('register')}
            >
              Sign Up
            </button>
          </div>

          <div className="auth-form">
            <input
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
            />
            <input
              placeholder="Password"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <button onClick={doAuth}>
              {mode === 'register' ? 'Create Account' : 'Access Inbox'}
            </button>
          </div>
        </div>
        {/* Toast Notifications */}
        <Toast toasts={toasts} removeToast={removeToast} />
      </div>
    )
  }

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className={`sidebar ${sidebarCollapsed ? 'collapsed' : ''}`}>
        <button 
          className="sidebar-collapse-btn"
          onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
          title={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {sidebarCollapsed ? '→' : '←'}
        </button>
        
        <div className="sidebar-header">
          <div className="sidebar-logo">✉</div>
          {!sidebarCollapsed && (
            <div>
              <div className="sidebar-title">uOttaMail</div>
              <div className="sidebar-subtitle">AI Inbox Firewall</div>
            </div>
          )}
        </div>

        <nav className="sidebar-nav">
          <button className={`nav-item ${activeView === 'inbox' ? 'active' : ''}`} onClick={() => setActiveView('inbox')}>
            📥 {!sidebarCollapsed && 'Inbox'}
          </button>
          <button className={`nav-item ${activeView === 'actions' ? 'active' : ''}`} onClick={() => setActiveView('actions')}>
            ✅ {!sidebarCollapsed && 'Actions'}
          </button>
          <button className="nav-item">⭐ {!sidebarCollapsed && 'Starred'}</button>
          <button className="nav-item">📤 {!sidebarCollapsed && 'Sent'}</button>
          <button className="nav-item">🚫 {!sidebarCollapsed && 'Spam'}</button>
        </nav>

        <button
          className="nav-item"
          style={{ marginTop: 'auto', color: '#ef4444' }}
          onClick={() => {
            localStorage.removeItem('jwt')
            setToken('')
          }}
        >
          ↪ {!sidebarCollapsed && 'Logout'}
        </button>

        {!sidebarCollapsed && (
          <div className="sidebar-footer">
            Powered by Solace Agent Mesh
          </div>
        )}
      </aside>

      {/* Main Content */}
      <main className="main-content">
        {activeView === 'inbox' ? (
          <>
            <header className="inbox-header">
              <div>
                <h2 className="inbox-title">Inbox</h2>
                <p className="inbox-subtitle">Realtime email stream with AI priority classification</p>
              </div>
              <button onClick={() => setIsComposeOpen(!isComposeOpen)}>
                + New Message
              </button>
            </header>

            <div className="inbox-container">
              {/* Email List */}
              <div className="email-list-pane" style={{ width: showEmailDetail ? emailPaneWidth : '100%', maxWidth: showEmailDetail ? emailPaneWidth : '100%' }}>
                {/* AI Search Bar - sticky at top */}
                <div className="ai-search-container">
                  <div className="ai-search-wrapper">
                    <input
                      type="text"
                      className="ai-search-input"
                      placeholder={aiEnabled ? "Search emails... (press Enter to ask AI)" : "Search emails..."}
                      value={searchQuery}
                      onChange={(e) => setSearchQuery(e.target.value)}
                      onKeyDown={handleSearchKeyDown}
                    />
                    <span className="ai-search-icon">🔍</span>
                    <button 
                      className={`ai-search-sparkle ${aiEnabled ? 'active' : ''}`}
                      onClick={() => setAiEnabled(!aiEnabled)}
                      title={aiEnabled ? 'AI search enabled - press Enter to ask' : 'AI search disabled'}
                    >
                      <span className="sparkle-icon">✨</span>
                      AI
                    </button>
                  </div>
                </div>

                {/* AI Response - scrolls with list */}
                {(isAiLoading || aiResponse) && aiEnabled && (
                  <div className="ai-chat-response">
                    <div className="ai-chat-header">
                      <span className="sparkle-icon">✨</span>
                      AI Assistant
                      <button 
                        className="close-btn"
                        onClick={() => { setAiResponse(null); setIsAiLoading(false); }}
                        title="Close AI response"
                      >
                        ✕
                      </button>
                    </div>
                    {isAiLoading ? (
                      <div className="ai-chat-loading">
                        <span>Thinking</span>
                        <div className="dots">
                          <div className="dot"></div>
                          <div className="dot"></div>
                          <div className="dot"></div>
                        </div>
                      </div>
                    ) : aiResponse ? (
                      <>
                        <div 
                          className="ai-chat-text" 
                          dangerouslySetInnerHTML={{ 
                            __html: formatAiResponse(aiResponse.message || aiResponse.response || 'Processing your query...', emails) 
                          }}
                          onClick={(e) => {
                            // Handle clicks on email ID links
                            if (e.target.classList.contains('ai-email-id-link')) {
                              const emailId = parseInt(e.target.dataset.emailId);
                              if (emailId) {
                                setSelectedId(emailId);
                                setShowEmailDetail(true);
                              }
                            }
                          }}
                        />
                        {/* Show related emails if any match subjects mentioned */}
                        {(() => {
                          const responseText = aiResponse.message || aiResponse.response || '';
                          const mentionedEmails = emails.filter(e => 
                            responseText.toLowerCase().includes(e.subject.toLowerCase().substring(0, 20))
                          ).slice(0, 5);
                          return mentionedEmails.length > 0 ? (
                            <div className="ai-chat-emails">
                              <div className="ai-chat-emails-title">📧 Related Emails:</div>
                              {mentionedEmails.map(e => (
                                <span 
                                  key={e.id} 
                                  className="ai-chat-email-link"
                                  onClick={() => { setSelectedId(e.id); setShowEmailDetail(true); }}
                                >
                                  {e.subject.substring(0, 40)}{e.subject.length > 40 ? '...' : ''}
                                </span>
                              ))}
                            </div>
                          ) : null;
                        })()}
                      </>
                    ) : null}
                  </div>
                )}

                {/* Text Search Results */}
                {searchQuery && searchResults.length > 0 && (
                  <div className="search-results">
                    <div className="search-results-header">
                      <span>📋 {searchResults.length} result{searchResults.length !== 1 ? 's' : ''}</span>
                      <button 
                        className="close-btn"
                        onClick={() => { setSearchQuery(''); setSearchResults([]); }}
                        title="Clear search"
                      >
                        ✕
                      </button>
                    </div>
                    {searchResults.map((email) => (
                      <div 
                        key={email.id} 
                        className="search-result-item"
                        onClick={() => { setSelectedId(email.id); setShowEmailDetail(true); }}
                      >
                        <div className="search-result-subject">{email.subject}</div>
                        <div className="search-result-meta">
                          From: {email.sender_username || 'unknown'} • {email.spam_label} • {email.priority || 'unrated'}
                        </div>
                        <div className="search-result-snippet">
                          {email.summary || email.body?.substring(0, 100) + '...'}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* Email List Items */}
                {emails.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-secondary)' }}>
                No emails found.
              </div>
            ) : (
              emails.map((e) => (
                <div
                  key={e.id}
                  onClick={() => { setSelectedId(e.id); setShowEmailDetail(true); }}
                  className={`email-row ${selected?.id === e.id ? 'selected' : ''}`}
                >
                  <div className={`email-dot priority-${(e.priority || 'Medium').toLowerCase()}`}></div>
                  <div className="email-meta">
                    <div className="email-sender">{e.sender_username || 'unknown'}</div>
                    <div className="email-subject">{e.subject}</div>
                    <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                      <span className={`email-badge spam-${e.spam_label}`}>
                        {e.spam_label || 'SCANNING'}
                      </span>
                      {e.priority && (
                        <span className="email-badge">
                          {e.priority}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              ))
            )}
          </div>

              {/* Resizer */}
              {showEmailDetail && (
                <div 
                  className={`pane-resizer ${isResizing ? 'resizing' : ''}`}
                  onMouseDown={handleMouseDown}
                />
              )}

          {/* Email Detail / Reading Pane */}
          {showEmailDetail && (
            <div className="email-detail-pane">
              <button 
                className="close-detail-btn"
                onClick={() => { setShowEmailDetail(false); setSelectedId(null); }}
                title="Close email detail"
              >
                ✕
              </button>
              {!selected ? (
                <div style={{ display: 'flex', height: '100%', alignItems: 'center', justifyContent: 'center', color: 'var(--text-secondary)' }}>
                  <p>Select an email to view details</p>
                </div>
              ) : (
                <div>
                  <div className="detail-header">
                    <h2 className="detail-subject">{selected.subject}</h2>
                    <div className="detail-meta">
                      From: <span style={{ color: 'var(--text-primary)' }}>{selected.sender_username}</span>
                    </div>
                  </div>

                  <div className="detail-body">
                    {selected.body}
                  </div>

                  <div style={{ borderTop: '1px solid var(--border-color)', paddingTop: '2rem' }}>
                    <h3 style={{ fontSize: '1.2rem' }}>AI Analysis</h3>

                    <div className="ai-cards-grid">
                      <div className="ai-card">
                        <span className="ai-label">Summary</span>
                        <div className="ai-value">
                          {selected.summary || 'Processing...'}
                        </div>
                      </div>

                      <div className="ai-card">
                        <span className="ai-label">Action Items</span>
                        <div className="action-items-list">
                          {selected.action_items && Array.isArray(selected.action_items) && selected.action_items.length > 0
                            ? selected.action_items.map((item, i) => (
                              <label key={i} className={`action-item-row ${item.done ? 'done' : ''}`}>
                                <input
                                  type="checkbox"
                                  checked={item.done || false}
                                  onChange={() => authed.toggleActionItem(selected.id, i)}
                                />
                                <div className="action-item-content">
                                  <span className="action-item-text">{typeof item === 'object' ? item.text : item}</span>
                                  {item.due && <span className="action-item-due">📅 {item.due}</span>}
                                  {item.assignee && <span className="action-item-assignee">👤 {item.assignee}</span>}
                                </div>
                              </label>
                            ))
                            : <div style={{ color: 'var(--text-secondary)', fontSize: '0.9rem' }}>No action items</div>
                          }
                        </div>
                      </div>

                    <div className="ai-card">
                      <span className="ai-label">Classification</span>
                      <div className="ai-row">
                        <span className="ai-row-label">Spam:</span>
                        <span style={{ color: selected.spam_label === 'spam' ? '#fca5a5' : '#86efac' }}>
                          {selected.spam_label || 'Processing...'}
                        </span>
                      </div>
                      <div className="ai-row">
                        <span className="ai-row-label">Priority:</span>
                        <span style={{ color: selected.priority === 'urgent' ? '#fca5a5' : selected.priority === 'high' ? '#fcd34d' : '#86efac' }}>
                          {selected.priority || 'Processing...'}
                        </span>
                      </div>
                      {selected.priority_reason && (
                        <div className="ai-explanation">
                          {selected.priority_reason}
                        </div>
                      )}
                    </div>

                    <div className="ai-card">
                      <span className="ai-label">Tone Analysis</span>
                      {selected.tone_emotion ? (
                        <>
                          <div className="ai-row">
                            <span className="ai-row-label">Emotion:</span>
                            <span style={{ color: 
                              ['angry', 'frustrated', 'annoyed', 'hostile'].includes(selected.tone_emotion?.toLowerCase()) ? '#fca5a5' :
                              ['anxious', 'worried', 'uncomfortable', 'nervous'].includes(selected.tone_emotion?.toLowerCase()) ? '#fcd34d' :
                              ['happy', 'excited', 'grateful', 'positive'].includes(selected.tone_emotion?.toLowerCase()) ? '#86efac' :
                              '#a5b4fc'
                            }}>{selected.tone_emotion}</span>
                            {selected.tone_confidence && (
                              <span className="ai-confidence">({selected.tone_confidence})</span>
                            )}
                          </div>
                          {selected.tone_explanation && (
                            <div className="ai-explanation">
                              {selected.tone_explanation}
                            </div>
                          )}
                        </>
                      ) : (
                        <div className="ai-value-muted">Processing...</div>
                      )}
                    </div>

                    <div className="ai-card">
                      <span className="ai-label">URL Security Scan</span>
                      {selected.url_scan_verdict ? (
                        (() => {
                          // Extract URL/domain from details if present (format: "URL domain.com ...")
                          const extractedUrl = selected.url_scan_details?.match(/^URL\s+(\S+)/i)?.[1] || null;
                          const hasThreats = (selected.url_scan_malicious_count > 0 || selected.url_scan_suspicious_count > 0);
                          
                          return (
                            <>
                              <div className="ai-row">
                                <span className="ai-row-label">Verdict:</span>
                                <span style={{
                                  color: selected.url_scan_verdict === 'SAFE' ? '#86efac' :
                                         selected.url_scan_verdict === 'SUSPICIOUS' ? '#fcd34d' : '#fca5a5'
                                }}>{selected.url_scan_verdict}</span>
                                {selected.url_scan_threat_level && selected.url_scan_verdict !== 'SAFE' && (
                                  <span className="ai-confidence">(Threat: {selected.url_scan_threat_level})</span>
                                )}
                              </div>
                              {hasThreats && (
                                <div className="ai-row" style={{ whiteSpace: 'nowrap' }}>
                                  <span style={{ color: '#fca5a5' }}>{selected.url_scan_malicious_count || 0} malicious</span>
                                  <span className="ai-separator">|</span>
                                  <span style={{ color: '#fcd34d' }}>{selected.url_scan_suspicious_count || 0} suspicious</span>
                                </div>
                              )}
                              {selected.url_scan_summary && (
                                <div className="ai-explanation">
                                  {selected.url_scan_summary}
                                </div>
                              )}
                              {extractedUrl && hasThreats && (
                                <a 
                                  href={`https://www.virustotal.com/gui/domain/${encodeURIComponent(extractedUrl)}`}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="ai-link"
                                >
                                  🔗 View {extractedUrl} on VirusTotal
                                </a>
                              )}
                            </>
                          );
                        })()
                      ) : (
                        <div className="ai-value-muted">No URLs detected or processing...</div>
                      )}
                    </div>
                  </div>

                  <div style={{ marginTop: '2rem' }}>
                    <button className="secondary" onClick={authed.refreshEmails} style={{ background: 'var(--bg-tertiary)', color: 'var(--text-primary)' }}>
                      Refresh Analysis
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>
          )}
        </div>
          </>
        ) : activeView === 'actions' ? (
          <>
            <header className="inbox-header">
              <div>
                <h2 className="inbox-title">Action Items</h2>
                <p className="inbox-subtitle">All your tasks from emails in one place</p>
              </div>
              <button onClick={() => authed.refreshActionItems()}>
                ↻ Refresh
              </button>
            </header>

            <div className="actions-container">
              {allActionItems.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-secondary)' }}>
                  <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>✅</div>
                  <div>No action items yet</div>
                  <div style={{ fontSize: '0.85rem', marginTop: '0.5rem' }}>Action items from your emails will appear here</div>
                </div>
              ) : (
                <div className="actions-list">
                  {allActionItems.map((item, idx) => (
                    <label
                      key={`${item.email_id}-${item.index}`}
                      className={`action-item-card ${item.done ? 'done' : ''}`}
                    >
                      <input
                        type="checkbox"
                        checked={item.done || false}
                        onChange={() => authed.toggleActionItem(item.email_id, item.index)}
                      />
                      <div className="action-item-card-content">
                        <div className="action-item-text">{item.text}</div>
                        <div className="action-item-meta">
                          <span className="action-item-email" onClick={(e) => { e.preventDefault(); setSelectedId(item.email_id); setShowEmailDetail(true); setActiveView('inbox'); }}>
                            📧 {item.email_subject}
                          </span>
                          {item.sender_username && <span>from {item.sender_username}</span>}
                          {item.due && <span className="action-item-due">📅 {item.due}</span>}
                          {item.assignee && <span className="action-item-assignee">👤 {item.assignee}</span>}
                        </div>
                      </div>
                    </label>
                  ))}
                </div>
              )}
            </div>
          </>
        ) : null}
      </main>

      {/* Compose Modal */}
      {isComposeOpen && (
        <div className="compose-modal">
          <div className="compose-header">
            <span>New Message</span>
            <button
              onClick={() => setIsComposeOpen(false)}
              style={{ background: 'transparent', padding: 0, width: 24 }}
            >
              ✕
            </button>
          </div>
          <div className="compose-body">
            <input
              placeholder="To: username"
              value={toUser}
              onChange={(e) => setToUser(e.target.value)}
            />
            <input
              placeholder="Subject"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
            />
            <textarea
              placeholder="Write your message..."
              value={body}
              onChange={(e) => setBody(e.target.value)}
              style={{ minHeight: 150 }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button onClick={() => { sendEmail(); setIsComposeOpen(false); }}>
                Send Message
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast Notifications */}
      <Toast toasts={toasts} removeToast={removeToast} />
    </div>
  )
}
