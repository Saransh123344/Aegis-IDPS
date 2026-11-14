import React, { useState, useEffect, useRef } from 'react';
import AnsiToHtml from 'ansi-to-html';

// Initialize the ANSI parser outside the component so it doesn't re-render constantly
const ansiConverter = new AnsiToHtml({
  newline: true,
  escapeXML: true,
  colors: {
    2: '#4ade80', // Map terminal green to Tailwind green-400
    3: '#facc15', // Map terminal yellow to Tailwind yellow-400
    1: '#f87171'  // Map terminal red to Tailwind red-400
  }
});

export default function AegisDashboard() {
  const [logs, setLogs] = useState([]);
  const [activeInvestigation, setActiveInvestigation] = useState(null);
  const logsEndRef = useRef(null);

  useEffect(() => {
    const eventSource = new EventSource("http://localhost:8000/stream");

    eventSource.onmessage = (event) => {
      const data = JSON.parse(event.data);

      if (data.type === "log") {
        setLogs((prev) => {
          const lastLog = prev[prev.length - 1];
          
          if (lastLog && lastLog.payload === data.payload) {
            return prev;
          }
          if (data.isSuspicious && lastLog && lastLog.isSuspicious && lastLog.ip === data.ip) {
            return prev;
          }

          const newLog = {
            id: data.timestamp + data.ip + Math.random(),
            timestamp: data.timestamp,
            ip: data.ip,
            payload: data.payload,
            isSuspicious: data.isSuspicious
          };
          return [...prev.slice(-40), newLog]; 
        });
      } 
      else if (data.type === "investigation_step") {
        setActiveInvestigation(prev => {
          if (!prev) {
            return { 
              targetIp: data.ip, 
              triggerPayload: data.triggerPayload || "Payload detected", 
              steps: [data.msg], 
              status: 'investigating' 
            };
          }
          if (prev.targetIp !== data.ip || prev.steps.includes(data.msg)) return prev;
          return { ...prev, steps: [...prev.steps, data.msg] };
        });
      }
      else if (data.type === "investigation_complete") {
        setActiveInvestigation(prev => {
          if (!prev) return null;
          return { ...prev, status: 'awaiting_approval' };
        });
      }
    };

    return () => eventSource.close();
  }, []);

  useEffect(() => {
    if (logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth', block: 'end' });
    }
  }, [logs]);

  const handleBlock = async () => {
    try {
      await fetch("http://localhost:8000/api/block", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: activeInvestigation.targetIp })
      });
    } catch (err) {
      console.error(err);
    }
    setActiveInvestigation(null);
  };

  return (
    <div className="h-screen w-full bg-[#000000] text-[#ffffff] font-sans p-8 flex flex-col overflow-hidden">
      
      <header className="flex justify-between items-center mb-10 w-full shrink-0">
        <div className="flex items-center gap-3">
          <div className="w-4 h-4 bg-gradient-to-br from-[#8052ff] to-[#15846e] rotate-45"></div>
          <span className="text-sm font-semibold tracking-widest uppercase">AegisNet</span>
        </div>
        <div className="text-[#9a9a9a] text-sm font-semibold tracking-widest uppercase">
          Live System // Loopback
        </div>
      </header>

      <main className="w-full flex gap-12 flex-1 min-h-0">
        
        <section className="w-[65%] flex flex-col min-h-0">
          <h1 className="text-[64px] leading-tight font-normal tracking-[-2px] mb-4 shrink-0">
            Network Telemetry
          </h1>
          
          <div className="flex-1 overflow-y-auto font-mono text-[13px] flex flex-col gap-2 pb-10 [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none]">
            {logs.map((log) => (
              <div 
                key={log.id} 
                className={`flex gap-6 transition-colors duration-300 ${
                  log.isSuspicious ? 'text-red-500 font-bold' : 'text-[#bdbdbd]'
                }`}
              >
                <span className="opacity-50 shrink-0 w-[100px]">{log.timestamp}</span>
                <span className="w-[120px] shrink-0">{log.ip}</span>
                <span className="truncate break-all">{log.payload}</span>
              </div>
            ))}
            <div ref={logsEndRef} className="h-1 shrink-0" />
          </div>
        </section>

        <section className="w-[35%] flex flex-col min-h-0 border-l border-[#222] pl-12">
          {activeInvestigation ? (
            <div className="flex flex-col h-full overflow-y-auto pr-4 [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none]">
              <span className="text-sm font-semibold text-[#ffb829] uppercase mb-4">
                Active Threat Investigation
              </span>
              <h2 className="text-[36px] font-normal mb-6">
                {activeInvestigation.targetIp}
              </h2>
              
              <div className="text-[16px] text-[#bdbdbd] mb-10 border border-red-900/50 bg-red-950/20 p-4 rounded-md">
                Trigger Payload: <br/>
                <span className="text-red-400 break-all">{activeInvestigation.triggerPayload}</span>
              </div>

              <div className="flex-1 flex flex-col gap-6">
                {activeInvestigation.steps.map((step, i) => (
                  <p 
                    key={i} 
                    className="text-[16px] text-[#ffffff] border-l-2 border-[#8052ff] pl-4 whitespace-pre-wrap"
                    // Safely render the parsed ANSI-to-HTML output
                    dangerouslySetInnerHTML={{ __html: ansiConverter.toHtml(step) }}
                  />
                ))}
                
                {activeInvestigation.status === 'investigating' && (
                  <p className="text-[16px] text-[#8052ff] animate-pulse pl-4 border-l-2 border-transparent">
                    CrewAI synthesizing data...
                  </p>
                )}
              </div>

              {activeInvestigation.status === 'awaiting_approval' && (
                <div className="flex gap-4 mt-10 pb-10 shrink-0">
                  <button 
                    onClick={handleBlock}
                    className="bg-[#8052ff] hover:bg-[#6c42db] text-white px-6 py-3 rounded-full text-sm font-semibold uppercase tracking-wider transition-colors"
                  >
                    Block IP
                  </button>
                  <button 
                    onClick={() => setActiveInvestigation(null)}
                    className="text-[#9a9a9a] hover:text-white px-6 py-3 text-sm font-semibold uppercase tracking-wider transition-colors"
                  >
                    Dismiss
                  </button>
                </div>
              )}
            </div>
          ) : (
            <div className="flex h-full items-center justify-center opacity-20">
              <p className="text-[16px] text-[#bdbdbd]">Awaiting anomalies...</p>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}