import { useState, useEffect, useRef, useCallback } from 'react';
import { Send, Server, Users, Radio, Shield, ShieldCheck, ShieldOff, Clock, Zap, MessageSquare, ChevronDown, ChevronUp, Activity, AlertCircle, Wifi, WifiOff } from 'lucide-react';

const API_BASE = ''; // Same origin

function useAPI(endpoint, interval = null) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const resp = await fetch(`${API_BASE}${endpoint}`);
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const json = await resp.json();
      setData(json);
      setError(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [endpoint]);

  useEffect(() => {
    fetchData();
    if (interval) {
      const id = setInterval(fetchData, interval);
      return () => clearInterval(id);
    }
  }, [fetchData, interval]);

  return { data, error, loading, refetch: fetchData };
}

function useSSE(onMessage) {
  const [connected, setConnected] = useState(false);
  const eventSourceRef = useRef(null);

  useEffect(() => {
    const connect = () => {
      const es = new EventSource(`${API_BASE}/events`);
      eventSourceRef.current = es;

      es.onopen = () => setConnected(true);
      es.onerror = () => {
        setConnected(false);
        es.close();
        setTimeout(connect, 3000);
      };
      es.addEventListener('round', (e) => {
        try {
          const data = JSON.parse(e.data);
          onMessage(data);
        } catch (err) {
          console.error('SSE parse error:', err);
        }
      });
    };

    connect();
    return () => eventSourceRef.current?.close();
  }, [onMessage]);

  return connected;
}

const phases = [
  { id: 'client', name: 'Client', icon: Users, desc: 'Clients blind & submit messages' },
  { id: 'aggregation', name: 'Aggregation', icon: Radio, desc: 'Aggregators combine messages' },
  { id: 'server', name: 'Server', icon: Server, desc: 'Servers remove blinding' },
  { id: 'broadcast', name: 'Broadcast', icon: Zap, desc: 'Messages revealed' },
];

function PhaseIndicator({ roundData }) {
  if (!roundData) {
    return (
      <div className="bg-slate-800 rounded-xl p-4 border border-slate-700 animate-pulse">
        <div className="h-5 bg-slate-700 rounded w-32 mb-3" />
        <div className="flex gap-2">
          {[0,1,2,3].map(i => <div key={i} className="flex-1 h-12 bg-slate-700 rounded-lg" />)}
        </div>
      </div>
    );
  }

  const { number, phase_index, progress } = roundData;

  return (
    <div className="bg-slate-800 rounded-xl p-4 border border-slate-700">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-base font-semibold text-white flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          Round {number}
        </h2>
        <span className="text-xs text-slate-400">Phase {phase_index + 1}/4</span>
      </div>
      
      <div className="flex items-center gap-2">
        {phases.map((phase, idx) => {
          const isActive = idx === phase_index;
          const isComplete = idx < phase_index;
          const Icon = phase.icon;
          
          return (
            <div key={phase.id} className="flex-1 flex flex-col items-center">
              <div className={`
                w-10 h-10 rounded-full flex items-center justify-center mb-1.5 transition-all duration-300
                ${isActive ? 'bg-cyan-500 text-white scale-110 shadow-lg shadow-cyan-500/30' : 
                  isComplete ? 'bg-green-500/20 text-green-400' : 
                  'bg-slate-700 text-slate-500'}
              `}>
                <Icon className="w-4 h-4" />
              </div>
              <span className={`text-xs font-medium ${isActive ? 'text-cyan-400' : 'text-slate-500'}`}>
                {phase.name}
              </span>
            </div>
          );
        })}
      </div>
      
      <div className="mt-3 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div 
          className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
          style={{ width: `${((phase_index + progress) / 4) * 100}%` }}
        />
      </div>
      
      <p className="text-xs text-slate-400 mt-2 text-center">
        {phases[phase_index]?.desc}
      </p>
    </div>
  );
}

function ServiceCard({ type, services }) {
  const [expanded, setExpanded] = useState(false);
  const icons = { servers: Server, aggregators: Radio, clients: Users };
  const Icon = icons[type];
  
  if (!services) return null;
  
  const healthy = services.filter(s => s.healthy).length;
  const attested = services.filter(s => s.attested).length;
  
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 overflow-hidden">
      <button 
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 flex items-center justify-between hover:bg-slate-700/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-500/20 flex items-center justify-center">
            <Icon className="w-5 h-5 text-blue-400" />
          </div>
          <div className="text-left">
            <h3 className="font-semibold text-white capitalize">{type}</h3>
            <p className="text-sm text-slate-400">
              {healthy}/{services.length} online
              {type !== 'clients' && ` • ${attested} attested`}
            </p>
          </div>
        </div>
        {expanded ? <ChevronUp className="w-5 h-5 text-slate-400" /> : <ChevronDown className="w-5 h-5 text-slate-400" />}
      </button>
      
      {expanded && (
        <div className="border-t border-slate-700 p-3 space-y-2 max-h-48 overflow-y-auto">
          {services.map((svc, idx) => (
            <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-slate-900/50">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${svc.healthy ? 'bg-green-400' : 'bg-red-400'}`} />
                <code className="text-xs text-slate-300 truncate max-w-[120px]">{svc.public_key.slice(0, 16)}...</code>
                {svc.is_leader && (
                  <span className="text-[10px] bg-yellow-500/20 text-yellow-400 px-1.5 py-0.5 rounded">LEADER</span>
                )}
              </div>
              {type !== 'clients' && (
                svc.attested ? 
                  <ShieldCheck className="w-4 h-4 text-green-400" /> : 
                  <ShieldOff className="w-4 h-4 text-red-400" />
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function MessagePanel({ messages, onSend, sending }) {
  const streamRef = useRef(null);
  const [message, setMessage] = useState('');
  const [bid, setBid] = useState(100);
  
  useEffect(() => {
    if (streamRef.current) {
      streamRef.current.scrollTop = 0;
    }
  }, [messages]);

  const handleSend = () => {
    if (!message.trim()) return;
    onSend(message, bid);
    setMessage('');
  };
  
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 flex flex-col h-[580px] shadow-[0_0_40px_rgba(6,182,212,0.08)]">
      <div className="p-4 border-b border-slate-700 flex items-center justify-between">
        <h2 className="font-semibold text-white flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-cyan-400" />
          Messages
        </h2>
        <span className="text-xs text-slate-400">{messages.length} received</span>
      </div>
      
      <div ref={streamRef} className="flex-1 overflow-y-auto p-4 space-y-3">
        {messages.length === 0 ? (
          <div className="h-full flex items-center justify-center text-slate-500">
            <p>Waiting for messages...</p>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <div key={`${msg.round}-${msg.offset}-${idx}`} className="bg-slate-900/50 rounded-lg p-3 border border-slate-700/50">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-medium text-cyan-400">Round {msg.round}</span>
                <span className="text-xs text-slate-500">{msg.time}</span>
              </div>
              <p className="text-sm text-slate-200 font-mono break-all">
                {msg.binary ? `[binary: ${msg.content.slice(0, 32)}...]` : msg.content}
              </p>
              <div className="flex gap-3 mt-2 text-xs text-slate-500">
                <span>Offset: {msg.offset}</span>
                <span>Size: {msg.size}b</span>
              </div>
            </div>
          ))
        )}
      </div>

      <div className="p-3 border-t border-slate-700 space-y-2">
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter your anonymous message..."
          className="w-full h-24 bg-slate-900 border border-slate-700 rounded-lg p-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 resize-none"
        />
        <div className="flex items-center gap-3">
          <div className="flex-1 flex items-center gap-2">
            <label className="text-xs text-slate-400 whitespace-nowrap">Bid</label>
            <input
              type="range"
              min="1"
              max="1000"
              value={bid}
              onChange={(e) => setBid(parseInt(e.target.value))}
              className="flex-1 accent-cyan-500 h-1.5"
            />
            <span className="text-sm font-semibold text-white w-10 text-right">{bid}</span>
          </div>
          <button
            onClick={handleSend}
            disabled={!message.trim() || sending}
            className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-500 text-white text-sm font-medium rounded-lg hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-1.5"
          >
            {sending ? (
              <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <Send className="w-3.5 h-3.5" />
            )}
            Send
          </button>
        </div>
      </div>
    </div>
  );
}

function ConfigPanel({ config }) {
  if (!config) {
    return (
      <div className="bg-slate-800 rounded-xl border border-slate-700 p-3 animate-pulse">
        <div className="h-4 bg-slate-700 rounded w-24 mb-3" />
        <div className="space-y-2">
          {[0,1,2,3].map(i => <div key={i} className="h-10 bg-slate-700 rounded-lg" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 p-3">
      <h2 className="font-semibold text-white flex items-center gap-2 mb-3 text-sm">
        <Activity className="w-4 h-4 text-cyan-400" />
        Protocol Config
      </h2>
      <div className="space-y-2 text-sm">
        <div className="bg-slate-900/50 rounded-lg p-2 flex items-center justify-between">
          <span className="text-slate-400 text-xs">Round Duration</span>
          <span className="text-white font-mono text-xs">{config.round_duration}</span>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-2 flex items-center justify-between">
          <span className="text-slate-400 text-xs">Message Capacity</span>
          <span className="text-white font-mono text-xs">{(config.message_length / 1024).toFixed(0)}KB</span>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-2 flex items-center justify-between">
          <span className="text-slate-400 text-xs">Auction Slots</span>
          <span className="text-white font-mono text-xs">{config.auction_slots}</span>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-2 flex items-center justify-between">
          <span className="text-slate-400 text-xs">Min Clients</span>
          <span className="text-white font-mono text-xs">{config.min_clients}</span>
        </div>
      </div>
    </div>
  );
}

function ConnectionStatus({ connected, error }) {
  return (
    <div className="flex items-center gap-2">
      {error ? (
        <>
          <AlertCircle className="w-4 h-4 text-red-400" />
          <span className="text-sm text-red-400">Error</span>
        </>
      ) : connected ? (
        <>
          <Wifi className="w-4 h-4 text-green-400" />
          <span className="text-sm text-slate-400">Connected</span>
        </>
      ) : (
        <>
          <WifiOff className="w-4 h-4 text-yellow-400 animate-pulse" />
          <span className="text-sm text-yellow-400">Connecting...</span>
        </>
      )}
    </div>
  );
}

// Mock data for design preview when backend is unavailable
const MOCK_ROUND_DATA = {
  number: 42,
  phase_index: 1,
  progress: 0.6,
};

const MOCK_SERVICES = {
  servers: [
    { public_key: 'srv1_a1b2c3d4e5f6g7h8i9j0', healthy: true, attested: true, is_leader: true },
    { public_key: 'srv2_k1l2m3n4o5p6q7r8s9t0', healthy: true, attested: true, is_leader: false },
    { public_key: 'srv3_u1v2w3x4y5z6a7b8c9d0', healthy: false, attested: false, is_leader: false },
  ],
  aggregators: [
    { public_key: 'agg1_e1f2g3h4i5j6k7l8m9n0', healthy: true, attested: true },
    { public_key: 'agg2_o1p2q3r4s5t6u7v8w9x0', healthy: true, attested: false },
  ],
  clients: [
    { public_key: 'cli1_y1z2a3b4c5d6e7f8g9h0', healthy: true },
    { public_key: 'cli2_i1j2k3l4m5n6o7p8q9r0', healthy: true },
    { public_key: 'cli3_s1t2u3v4w5x6y7z8a9b0', healthy: true },
    { public_key: 'cli4_c1d2e3f4g5h6i7j8k9l0', healthy: false },
    { public_key: 'cli5_m1n2o3p4q5r6s7t8u9v0', healthy: true },
  ],
};

const MOCK_CONFIG = {
  round_duration: '10s',
  message_length: 102400,
  auction_slots: 20,
  min_clients: 3,
};

export default function ADCNetDemo() {
  const [messages, setMessages] = useState([]);
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState(null);

  const { data: configData, error: configError } = useAPI('/api/config', 30000);
  const { data: servicesData, error: servicesError } = useAPI('/api/services', 15000);
  const { data: roundDataApi, error: roundError } = useAPI('/api/round', 1000);

  // Use mock data when backend is unavailable
  const config = configData || MOCK_CONFIG;
  const services = servicesData || MOCK_SERVICES;
  const roundData = roundDataApi || MOCK_ROUND_DATA;

  const handleRoundEvent = useCallback((event) => {
    if (event.messages && event.messages.length > 0) {
      const newMessages = event.messages.map(msg => ({
        ...msg,
        round: event.round,
        time: new Date().toLocaleTimeString(),
      }));
      setMessages(prev => [...newMessages, ...prev].slice(0, 50));
    }
  }, []);

  const sseConnected = useSSE(handleRoundEvent);

  const handleSend = async (message, bid) => {
    setSending(true);
    setSendError(null);
    
    try {
      const resp = await fetch(`${API_BASE}/api/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message, bid }),
      });
      
      const data = await resp.json();
      
      if (!data.success) {
        throw new Error(data.error || 'Failed to send');
      }
      
      // Show success briefly
      setSendError({ type: 'success', message: `Scheduled for round ${data.scheduled_for}` });
      setTimeout(() => setSendError(null), 3000);
    } catch (e) {
      setSendError({ type: 'error', message: e.message });
    } finally {
      setSending(false);
    }
  };

  const hasError = configError || servicesError || roundError;

  return (
    <div className="min-h-screen bg-slate-900 text-white">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <Shield className="w-6 h-6" />
            </div>
            <div>
              <h1 className="font-bold text-xl">ADCNet</h1>
              <p className="text-xs text-slate-400">Anonymous Distributed Communication</p>
            </div>
          </div>
          <ConnectionStatus connected={sseConnected && !hasError} error={hasError} />
        </div>
      </header>
      
      {/* Error Banner */}
      {hasError && (
        <div className="bg-red-500/10 border-b border-red-500/20 px-6 py-3">
          <div className="max-w-7xl mx-auto flex items-center gap-2 text-red-400 text-sm">
            <AlertCircle className="w-4 h-4" />
            <span>Connection issues: {configError || servicesError || roundError}</span>
          </div>
        </div>
      )}

      {/* Send Feedback */}
      {sendError && (
        <div className={`${sendError.type === 'success' ? 'bg-green-500/10 border-green-500/20' : 'bg-red-500/10 border-red-500/20'} border-b px-6 py-3`}>
          <div className={`max-w-7xl mx-auto text-sm ${sendError.type === 'success' ? 'text-green-400' : 'text-red-400'}`}>
            {sendError.type === 'success' ? '✓' : '✗'} {sendError.message}
          </div>
        </div>
      )}
      
      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-6 py-8 space-y-6">
        {/* Phase Indicator */}
        <PhaseIndicator roundData={roundData} />
        
        {/* Grid Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Column - Network */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Network Topology</h2>
            <ServiceCard type="servers" services={services?.servers} />
            <ServiceCard type="aggregators" services={services?.aggregators} />
            <ServiceCard type="clients" services={services?.clients} />
          </div>
          
          {/* Middle Column - Messages & Send */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Live Output</h2>
            <MessagePanel messages={messages} onSend={handleSend} sending={sending} />
          </div>
          
          {/* Right Column - Config */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Protocol</h2>
            <ConfigPanel config={config} />
          </div>
        </div>
      </main>
      
      {/* Footer */}
      <footer className="border-t border-slate-800 mt-12 py-6">
        <div className="max-w-7xl mx-auto px-6 text-center text-sm text-slate-500">
          <p>ADCNet Demo • XOR-based anonymous broadcast with auction scheduling</p>
          <p className="mt-1">Built with TEE attestation for integrity verification</p>
        </div>
      </footer>
    </div>
  );
}
