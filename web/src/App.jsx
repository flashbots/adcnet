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
      <div className="bg-slate-800 rounded-xl p-6 border border-slate-700 animate-pulse">
        <div className="h-6 bg-slate-700 rounded w-32 mb-4" />
        <div className="flex gap-2">
          {[0,1,2,3].map(i => <div key={i} className="flex-1 h-16 bg-slate-700 rounded-lg" />)}
        </div>
      </div>
    );
  }

  const { number, phase_index, progress } = roundData;

  return (
    <div className="bg-slate-800 rounded-xl p-6 border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-white flex items-center gap-2">
          <Clock className="w-5 h-5 text-cyan-400" />
          Round {number}
        </h2>
        <span className="text-sm text-slate-400">Phase {phase_index + 1}/4</span>
      </div>
      
      <div className="flex items-center gap-2">
        {phases.map((phase, idx) => {
          const isActive = idx === phase_index;
          const isComplete = idx < phase_index;
          const Icon = phase.icon;
          
          return (
            <div key={phase.id} className="flex-1 flex flex-col items-center">
              <div className={`
                w-12 h-12 rounded-full flex items-center justify-center mb-2 transition-all duration-300
                ${isActive ? 'bg-cyan-500 text-white scale-110 shadow-lg shadow-cyan-500/30' : 
                  isComplete ? 'bg-green-500/20 text-green-400' : 
                  'bg-slate-700 text-slate-500'}
              `}>
                <Icon className="w-5 h-5" />
              </div>
              <span className={`text-xs font-medium ${isActive ? 'text-cyan-400' : 'text-slate-500'}`}>
                {phase.name}
              </span>
            </div>
          );
        })}
      </div>
      
      <div className="mt-4 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div 
          className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
          style={{ width: `${((phase_index + progress) / 4) * 100}%` }}
        />
      </div>
      
      <p className="text-sm text-slate-400 mt-3 text-center">
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

function MessageStream({ messages }) {
  const streamRef = useRef(null);
  
  useEffect(() => {
    if (streamRef.current) {
      streamRef.current.scrollTop = 0;
    }
  }, [messages]);
  
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 flex flex-col h-80">
      <div className="p-4 border-b border-slate-700 flex items-center justify-between">
        <h2 className="font-semibold text-white flex items-center gap-2">
          <MessageSquare className="w-5 h-5 text-cyan-400" />
          Message Stream
        </h2>
        <span className="text-xs text-slate-400">{messages.length} messages</span>
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
    </div>
  );
}

function SendMessage({ onSend, sending }) {
  const [message, setMessage] = useState('');
  const [bid, setBid] = useState(100);
  
  const handleSend = () => {
    if (!message.trim()) return;
    onSend(message, bid);
    setMessage('');
  };
  
  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
      <h2 className="font-semibold text-white flex items-center gap-2 mb-4">
        <Send className="w-5 h-5 text-cyan-400" />
        Send Anonymous Message
      </h2>
      
      <div className="space-y-4">
        <textarea
          value={message}
          onChange={(e) => setMessage(e.target.value)}
          placeholder="Enter your message..."
          className="w-full h-24 bg-slate-900 border border-slate-700 rounded-lg p-3 text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500/50 resize-none"
        />
        
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <label className="text-xs text-slate-400 mb-1 block">Bid Value</label>
            <input
              type="range"
              min="1"
              max="1000"
              value={bid}
              onChange={(e) => setBid(parseInt(e.target.value))}
              className="w-full accent-cyan-500"
            />
          </div>
          <div className="text-right">
            <span className="text-2xl font-bold text-white">{bid}</span>
            <span className="text-xs text-slate-400 block">priority</span>
          </div>
        </div>
        
        <button
          onClick={handleSend}
          disabled={!message.trim() || sending}
          className="w-full py-3 bg-gradient-to-r from-cyan-500 to-blue-500 text-white font-semibold rounded-lg hover:from-cyan-400 hover:to-blue-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2"
        >
          {sending ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Submitting...
            </>
          ) : (
            <>
              <Send className="w-4 h-4" />
              Send Anonymously
            </>
          )}
        </button>
        
        <p className="text-xs text-slate-500 text-center">
          ⚠️ Demo mode: Message routed through demo client
        </p>
      </div>
    </div>
  );
}

function ConfigPanel({ config }) {
  if (!config) {
    return (
      <div className="bg-slate-800 rounded-xl border border-slate-700 p-4 animate-pulse">
        <div className="h-5 bg-slate-700 rounded w-32 mb-4" />
        <div className="grid grid-cols-2 gap-3">
          {[0,1,2,3].map(i => <div key={i} className="h-16 bg-slate-700 rounded-lg" />)}
        </div>
      </div>
    );
  }

  return (
    <div className="bg-slate-800 rounded-xl border border-slate-700 p-4">
      <h2 className="font-semibold text-white flex items-center gap-2 mb-4">
        <Activity className="w-5 h-5 text-cyan-400" />
        Protocol Config
      </h2>
      <div className="grid grid-cols-2 gap-3 text-sm">
        <div className="bg-slate-900/50 rounded-lg p-3">
          <span className="text-slate-400 text-xs">Round Duration</span>
          <p className="text-white font-mono">{config.round_duration}</p>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-3">
          <span className="text-slate-400 text-xs">Message Capacity</span>
          <p className="text-white font-mono">{(config.message_length / 1024).toFixed(0)}KB</p>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-3">
          <span className="text-slate-400 text-xs">Auction Slots</span>
          <p className="text-white font-mono">{config.auction_slots}</p>
        </div>
        <div className="bg-slate-900/50 rounded-lg p-3">
          <span className="text-slate-400 text-xs">Min Clients</span>
          <p className="text-white font-mono">{config.min_clients}</p>
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
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState(null);

  const { data: config, error: configError } = useAPI('/api/config', 30000);
  const { data: services, error: servicesError } = useAPI('/api/services', 15000);
  const { data: roundData, error: roundError } = useAPI('/api/round', 1000);

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
          
          {/* Middle Column - Messages */}
          <div className="lg:col-span-1">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider mb-4">Live Output</h2>
            <MessageStream messages={messages} />
          </div>
          
          {/* Right Column - Send & Config */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">Participate</h2>
            <SendMessage onSend={handleSend} sending={sending} />
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
