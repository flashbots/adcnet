import { useState, useEffect, useRef, useCallback } from 'react';

const API_BASE = '';

// Icons as simple SVG components
const Shield = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>;
const Server = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>;
const Users = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>;
const Radio = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>;
const Clock = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>;
const Zap = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>;
const MessageSquare = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>;
const Send = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="22" y1="2" x2="11" y2="13"/><polygon points="22 2 15 22 11 13 2 9 22 2"/></svg>;
const ChevronDown = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>;
const ChevronUp = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="18 15 12 9 6 15"/></svg>;
const Activity = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>;
const AlertCircle = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>;
const Wifi = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>;
const WifiOff = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="1" y1="1" x2="23" y2="23"/><path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55"/><path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39"/><path d="M10.71 5.05A16 16 0 0 1 22.58 9"/><path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg>;
const ShieldCheck = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>;
const ShieldOff = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"/><path d="M4.73 4.73 4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"/><line x1="1" y1="1" x2="23" y2="23"/></svg>;
const Gavel = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="m14 13-7.5 7.5c-.83.83-2.17.83-3 0 0 0 0 0 0 0a2.12 2.12 0 0 1 0-3L11 10"/><path d="m16 16 6-6"/><path d="m8 8 6-6"/><path d="m9 7 8 8"/><path d="m21 11-8-8"/></svg>;
const TrendingUp = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 6 13.5 15.5 8.5 10.5 1 18"/><polyline points="17 6 23 6 23 12"/></svg>;
const TrendingDown = ({ className }) => <svg className={className} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="23 18 13.5 8.5 8.5 13.5 1 6"/><polyline points="17 18 23 18 23 12"/></svg>;

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
  round_duration: '10000000000',
  message_length: 512000,
  auction_slots: 10,
  min_clients: 3,
};

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

function formatDuration(durationStr) {
  if (!durationStr) return '-';
  const ns = parseInt(durationStr, 10);
  if (isNaN(ns)) return durationStr;
  if (ns >= 1e9) return `${ns / 1e9}s`;
  if (ns >= 1e6) return `${ns / 1e6}ms`;
  if (ns >= 1e3) return `${ns / 1e3}µs`;
  return `${ns}ns`;
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
        className="w-full p-3 flex items-center justify-between hover:bg-slate-700/50 transition-colors"
      >
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-blue-500/20 flex items-center justify-center">
            <Icon className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-left">
            <h3 className="font-semibold text-white capitalize text-sm">{type}</h3>
            <p className="text-xs text-slate-400">
              {healthy}/{services.length} online
              {type !== 'clients' && ` • ${attested} attested`}
            </p>
          </div>
        </div>
        {expanded ? <ChevronUp className="w-4 h-4 text-slate-400" /> : <ChevronDown className="w-4 h-4 text-slate-400" />}
      </button>
      
      {expanded && (
        <div className="border-t border-slate-700 p-2 space-y-1.5 max-h-40 overflow-y-auto">
          {services.map((svc, idx) => (
            <div key={idx} className="flex items-center justify-between p-2 rounded-lg bg-slate-900/50">
              <div className="flex items-center gap-2">
                <div className={`w-2 h-2 rounded-full ${svc.healthy ? 'bg-green-400' : 'bg-red-400'}`} />
                <code className="text-xs text-slate-300 truncate max-w-[100px]">{svc.public_key.slice(0, 12)}...</code>
                {svc.is_leader && (
                  <span className="text-[10px] bg-yellow-500/20 text-yellow-400 px-1.5 py-0.5 rounded">LEADER</span>
                )}
              </div>
              {type !== 'clients' && (
                svc.attested ? 
                  <ShieldCheck className="w-3.5 h-3.5 text-green-400" /> : 
                  <ShieldOff className="w-3.5 h-3.5 text-red-400" />
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

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && e.ctrlKey) {
      e.preventDefault();
      handleSend();
    }
  };
  
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 flex flex-col h-full">
      <div className="p-3 border-b border-slate-700 space-y-2">
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Enter your anonymous message... (Ctrl+Enter to send)"
          className="w-full h-16 bg-slate-900 border border-slate-700 rounded-lg p-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 resize-none"
        />
        <div className="flex items-center gap-3">
          <div className="flex-1 flex items-center gap-2">
            <label className="text-xs text-slate-400">Bid</label>
            <input
              type="range"
              min="1"
              max="1000"
              value={bid}
              onChange={(e) => setBid(parseInt(e.target.value))}
              className="flex-1 accent-cyan-500 h-1"
            />
            <span className="text-xs font-semibold text-white w-8 text-right">{bid}</span>
          </div>
          <button
            onClick={handleSend}
            disabled={!message.trim() || sending}
            className="px-3 py-1.5 bg-gradient-to-r from-cyan-500 to-blue-500 text-white text-xs font-medium rounded-lg hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-1.5"
          >
            {sending ? (
              <div className="w-3 h-3 border-2 border-white/30 border-t-white rounded-full animate-spin" />
            ) : (
              <Send className="w-3 h-3" />
            )}
            Send
          </button>
        </div>
      </div>

      <div className="p-3 border-b border-slate-700 flex items-center justify-between">
        <h2 className="font-semibold text-white flex items-center gap-2 text-sm">
          <MessageSquare className="w-4 h-4 text-cyan-400" />
          Messages
        </h2>
        <span className="text-xs text-slate-400">{messages.length} received</span>
      </div>
      
      <div ref={streamRef} className="flex-1 overflow-y-auto p-3 space-y-2 min-h-0">
        {messages.length === 0 ? (
          <div className="h-24 flex items-center justify-center text-slate-500 text-sm">
            <p>Waiting for messages...</p>
          </div>
        ) : (
          messages.map((msg, idx) => (
            <div key={`${msg.round}-${msg.offset}-${idx}`} className="bg-slate-900/50 rounded-lg p-2.5 border border-slate-700/50">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-medium text-cyan-400">Round {msg.round}</span>
                <span className="text-xs text-slate-500">{msg.time}</span>
              </div>
              <p className="text-xs text-slate-200 font-mono break-all">
                {msg.binary ? `[binary: ${msg.content.slice(0, 32)}...]` : msg.content}
              </p>
              <div className="flex gap-3 mt-1.5 text-xs text-slate-500">
                <span>Offset: {msg.offset}</span>
                <span>Size: {msg.size}b</span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function BidStream({ bids }) {
  const streamRef = useRef(null);
  
  useEffect(() => {
    if (streamRef.current) {
      streamRef.current.scrollTop = 0;
    }
  }, [bids]);
  
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 flex flex-col h-full">
      <div className="p-3 border-b border-slate-700 flex items-center justify-between">
        <h2 className="font-semibold text-white flex items-center gap-2 text-sm">
          <Gavel className="w-4 h-4 text-amber-400" />
          Auction Bids
        </h2>
        <span className="text-xs text-slate-400">{bids.length} bids</span>
      </div>
      
      <div ref={streamRef} className="flex-1 overflow-y-auto p-3 space-y-2 min-h-0">
        {bids.length === 0 ? (
          <div className="h-24 flex items-center justify-center text-slate-500 text-sm">
            <p>No bids yet...</p>
          </div>
        ) : (
          bids.map((bid, idx) => (
            <div 
              key={`${bid.round}-${bid.message_hash}-${idx}`} 
              className={`rounded-lg p-2.5 border ${
                bid.won 
                  ? 'bg-green-900/20 border-green-700/50' 
                  : 'bg-slate-900/50 border-slate-700/50'
              }`}
            >
              <div className="flex items-center justify-between mb-1.5">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-amber-400">Round {bid.round}</span>
                  {bid.won ? (
                    <span className="text-[10px] bg-green-500/20 text-green-400 px-1.5 py-0.5 rounded flex items-center gap-1">
                      <TrendingUp className="w-2.5 h-2.5" /> WON
                    </span>
                  ) : (
                    <span className="text-[10px] bg-red-500/20 text-red-400 px-1.5 py-0.5 rounded flex items-center gap-1">
                      <TrendingDown className="w-2.5 h-2.5" /> LOST
                    </span>
                  )}
                </div>
                <span className="text-xs text-slate-500">{bid.time}</span>
              </div>
              <div className="flex items-center justify-between">
                <code className="text-xs text-slate-400 font-mono">
                  {bid.message_hash}...
                </code>
                <div className="flex gap-3 text-xs">
                  <span className="text-amber-400 font-semibold">⚡ {bid.weight}</span>
                  <span className="text-slate-500">{bid.size}b</span>
                </div>
              </div>
            </div>
          ))
        )}
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
          {[0,1,2,3].map(i => <div key={i} className="h-8 bg-slate-700 rounded-lg" />)}
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
      <div className="space-y-1.5 text-sm">
        <div className="bg-slate-900/50 rounded-lg p-2 flex items-center justify-between">
          <span className="text-slate-400 text-xs">Round Duration</span>
          <span className="text-white font-mono text-xs">{formatDuration(config.round_duration)}</span>
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

export default function ADCNetDemo() {
  const [messages, setMessages] = useState([]);
  const [bids, setBids] = useState([]);
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
    const timestamp = new Date().toLocaleTimeString();
    
    if (event.messages && event.messages.length > 0) {
      const newMessages = event.messages.map(msg => ({
        ...msg,
        round: event.round,
        time: timestamp,
      })).filter((item, index) => messages.indexOf(item) === -1);
      // Max 50, remove duplicates (they are event issues, not actual duplicates)
      setMessages(prev => [...newMessages, ...prev].slice(0, 50));
    }
    
    if (event.bids && event.bids.length > 0) {
      const newBids = event.bids.map(bid => ({
        ...bid,
        round: event.round,
        time: timestamp,
      }));
      setBids(prev => [...newBids, ...prev].slice(0, 50));
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
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <h1 className="font-bold text-lg">ADCNet</h1>
              <p className="text-xs text-slate-400">Anonymous Distributed Communication</p>
            </div>
          </div>
          <ConnectionStatus connected={sseConnected && !hasError} error={hasError} />
        </div>
      </header>
      
      {hasError && (
        <div className="bg-red-500/10 border-b border-red-500/20 px-4 py-2">
          <div className="max-w-7xl mx-auto flex items-center gap-2 text-red-400 text-xs">
            <AlertCircle className="w-3.5 h-3.5" />
            <span>Connection issues - showing mock data</span>
          </div>
        </div>
      )}

      {sendError && (
        <div className={`${sendError.type === 'success' ? 'bg-green-500/10 border-green-500/20' : 'bg-red-500/10 border-red-500/20'} border-b px-4 py-2`}>
          <div className={`max-w-7xl mx-auto text-xs ${sendError.type === 'success' ? 'text-green-400' : 'text-red-400'}`}>
            {sendError.type === 'success' ? '✓' : '✗'} {sendError.message}
          </div>
        </div>
      )}
      
      <main className="max-w-7xl mx-auto px-4 py-4 space-y-4">
        <PhaseIndicator roundData={roundData} />
        
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4" style={{ minHeight: '380px' }}>
          <div className="space-y-3">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Network</h2>
            <ServiceCard type="servers" services={services?.servers} />
            <ServiceCard type="aggregators" services={services?.aggregators} />
            <ServiceCard type="clients" services={services?.clients} />
            <ConfigPanel config={config} />
          </div>
          
          <div className="lg:col-span-2 flex flex-col">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Messages</h2>
            <div className="flex-1">
              <MessagePanel messages={messages} onSend={handleSend} sending={sending} />
            </div>
          </div>
          
          <div className="flex flex-col">
            <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">Auction</h2>
            <div className="flex-1">
              <BidStream bids={bids} />
            </div>
          </div>
        </div>
      </main>
      
      <footer className="border-t border-slate-800 mt-6 py-4">
        <div className="max-w-7xl mx-auto px-4 text-center text-xs text-slate-500">
          <p>ADCNet Demo • XOR-based anonymous broadcast with auction scheduling</p>
        </div>
      </footer>
    </div>
  );
}
